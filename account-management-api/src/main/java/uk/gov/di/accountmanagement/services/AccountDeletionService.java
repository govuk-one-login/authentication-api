package uk.gov.di.accountmanagement.services;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.accountmanagement.entity.AccountDeletionReason;
import uk.gov.di.accountmanagement.entity.NotificationType;
import uk.gov.di.accountmanagement.entity.NotifyRequest;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.auditevents.entity.AuthDeleteAccount;
import uk.gov.di.authentication.auditevents.services.StructuredAuditService;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.exceptions.UnsuccessfulAccountDataApiResponseException;
import uk.gov.di.authentication.shared.helpers.ClientSessionIdHelper;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.helpers.IpAddressHelper;
import uk.gov.di.authentication.shared.helpers.LocaleHelper;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.helpers.RequestHeaderHelper;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.AccountDataApiService;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.SerializationService;

import java.time.Clock;

import static uk.gov.di.authentication.shared.domain.RequestHeaders.SESSION_ID_HEADER;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.LogFieldName.PERSISTENT_SESSION_ID;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachLogFieldToLogs;

public class AccountDeletionService {
    private static final Logger LOG = LogManager.getLogger(AccountDeletionService.class);

    private final AuthenticationService authenticationService;
    private final AwsSqsClient sqsClient;
    private final StructuredAuditService structuredAuditService;
    private final ConfigurationService configurationService;
    private final DynamoDeleteService dynamoDeleteService;
    private final AccountDataApiService accountDataApiService;
    private final Json objectMapper = SerializationService.getInstance();

    public AccountDeletionService(
            AuthenticationService authenticationService,
            AwsSqsClient sqsClient,
            StructuredAuditService structuredAuditService,
            ConfigurationService configurationService,
            DynamoDeleteService dynamoDeleteService,
            AccountDataApiService accountDataApiService) {
        this.authenticationService = authenticationService;
        this.sqsClient = sqsClient;
        this.structuredAuditService = structuredAuditService;
        this.configurationService = configurationService;
        this.dynamoDeleteService = dynamoDeleteService;
        this.accountDataApiService = accountDataApiService;
    }

    public AccountDeletionService(
            AuthenticationService authenticationService,
            AwsSqsClient sqsClient,
            StructuredAuditService structuredAuditService,
            ConfigurationService configurationService,
            DynamoDeleteService dynamoDeleteService) {
        this(
                authenticationService,
                sqsClient,
                structuredAuditService,
                configurationService,
                dynamoDeleteService,
                null);
    }

    /**
     * Removes a user account directly via DynamoDB.
     *
     * <p>This method calculates the internal common subject identifier, deletes the user's account
     * records from DynamoDB directly, optionally sends a deletion notification via SQS, and emits a
     * standard audit event.
     *
     * @param userProfile The profile of the user whose account is being deleted.
     * @param txmaAuditEncoded The encoded TxMA audit information.
     * @param reason The reason for the account deletion.
     * @param sendNotification {@code true} to send an account deletion email notification; {@code
     *     false} otherwise.
     */
    public void removeAccount(
            UserProfile userProfile,
            String txmaAuditEncoded,
            AccountDeletionReason reason,
            boolean sendNotification) {
        var internalCommonSubjectIdentifier = calculateICS(userProfile);

        dynamoDeleteService.deleteAccount(
                userProfile.getEmail(),
                internalCommonSubjectIdentifier.getValue(),
                userProfile.getPublicSubjectID());
        LOG.info("User account deleted via DynamoDB directly, not via ADAPI");

        if (sendNotification) sendNotifyRequest(userProfile);

        emitAuditEvent(userProfile, txmaAuditEncoded, reason, internalCommonSubjectIdentifier);
    }

    /**
     * Removes a user account directly via DynamoDB, incorporating HTTP request context for enriched
     * auditing.
     *
     * <p>This method performs a direct DynamoDB deletion and optionally sends a notification.
     * Unlike the standard method, it extracts IP addresses, session IDs, and client IDs from the
     * provided API Gateway request event to construct a more detailed audit context.
     *
     * @param input The API Gateway request event containing headers and context for auditing.
     * @param userProfile The profile of the user whose account is being deleted.
     * @param txmaAuditEncoded The encoded TxMA audit information.
     * @param reason The reason for the account deletion.
     * @param sendNotification {@code true} to send an account deletion email notification; {@code
     *     false} otherwise.
     */
    public void removeAccount(
            APIGatewayProxyRequestEvent input,
            UserProfile userProfile,
            String txmaAuditEncoded,
            AccountDeletionReason reason,
            boolean sendNotification) {
        var internalCommonSubjectIdentifier = calculateICS(userProfile);

        dynamoDeleteService.deleteAccount(
                userProfile.getEmail(),
                internalCommonSubjectIdentifier.getValue(),
                userProfile.getPublicSubjectID());
        LOG.info("User account deleted via DynamoDB directly, not via ADAPI");

        if (sendNotification) sendNotifyRequest(userProfile);

        emitAuditEvent(
                input, userProfile, txmaAuditEncoded, reason, internalCommonSubjectIdentifier);
    }

    /**
     * Removes a user account by delegating to the Account Data API.
     *
     * <p>This method deletes the user by invoking the external Account Data API using the provided
     * authentication token. It optionally sends a deletion notification via SQS and emits a
     * standard audit event.
     *
     * @param userProfile The profile of the user whose account is being deleted.
     * @param txmaAuditEncoded The encoded TxMA audit information.
     * @param reason The reason for the account deletion.
     * @param sendNotification {@code true} to send an account deletion email notification; {@code
     *     false} otherwise.
     * @param accountDataApiToken The authorization token required to authenticate with the Account
     *     Data API.
     */
    public void removeAccount(
            UserProfile userProfile,
            String txmaAuditEncoded,
            AccountDeletionReason reason,
            boolean sendNotification,
            String accountDataApiToken) {
        var internalCommonSubjectIdentifier = calculateICS(userProfile);

        LOG.info("Deleting user account");

        deleteAccountViaDataApi(userProfile.getPublicSubjectID(), accountDataApiToken);

        if (sendNotification) sendNotifyRequest(userProfile);

        emitAuditEvent(userProfile, txmaAuditEncoded, reason, internalCommonSubjectIdentifier);
    }

    /**
     * Removes a user account by delegating to the Account Data API, incorporating HTTP request
     * context for enriched auditing.
     *
     * <p>This method deletes the user via the external Account Data API and optionally sends a
     * notification. It extracts IP addresses, session IDs, and client IDs from the provided API
     * Gateway request event to construct a highly detailed audit context.
     *
     * @param input The API Gateway request event containing headers and context for auditing.
     * @param userProfile The profile of the user whose account is being deleted.
     * @param txmaAuditEncoded The encoded TxMA audit information.
     * @param reason The reason for the account deletion.
     * @param sendNotification {@code true} to send an account deletion email notification; {@code
     *     false} otherwise.
     * @param accountDataApiToken The authorization token required to authenticate with the Account
     *     Data API.
     */
    public void removeAccount(
            APIGatewayProxyRequestEvent input,
            UserProfile userProfile,
            String txmaAuditEncoded,
            AccountDeletionReason reason,
            boolean sendNotification,
            String accountDataApiToken) {
        var internalCommonSubjectIdentifier = calculateICS(userProfile);

        LOG.info("Deleting user account");

        deleteAccountViaDataApi(userProfile.getPublicSubjectID(), accountDataApiToken);

        if (sendNotification) sendNotifyRequest(userProfile);

        emitAuditEvent(
                input, userProfile, txmaAuditEncoded, reason, internalCommonSubjectIdentifier);
    }

    private void sendNotifyRequest(UserProfile userProfile) {
        try {
            LOG.info("User account removed. Adding notification message to SQS queue");
            NotifyRequest notifyRequest =
                    new NotifyRequest(
                            userProfile.getEmail(),
                            NotificationType.DELETE_ACCOUNT,
                            LocaleHelper.SupportedLanguage.EN);
            sqsClient.send(objectMapper.writeValueAsString((notifyRequest)));
        } catch (Exception e) {
            LOG.error("Failed to send account deletion email: ", e);
        }
    }

    private void emitAuditEvent(
            UserProfile userProfile,
            String txmaAuditEncoded,
            AccountDeletionReason reason,
            Subject internalCommonSubjectIdentifier) {
        try {
            var auditEvent =
                    createAuditEvent(
                            userProfile, txmaAuditEncoded, reason, internalCommonSubjectIdentifier);
            structuredAuditService.submitAuditEvent(auditEvent);
        } catch (Exception e) {
            LOG.error("Failed to audit account deletion: ", e);
        }
    }

    private void emitAuditEvent(
            APIGatewayProxyRequestEvent input,
            UserProfile userProfile,
            String txmaAuditEncoded,
            AccountDeletionReason reason,
            Subject internalCommonSubjectIdentifier) {

        try {
            var auditEvent =
                    createAuditEvent(
                            input,
                            userProfile,
                            txmaAuditEncoded,
                            reason,
                            internalCommonSubjectIdentifier);
            structuredAuditService.submitAuditEvent(auditEvent);
        } catch (Exception e) {
            LOG.error("Failed to audit account deletion: ", e);
        }
    }

    private static AuthDeleteAccount createAuditEvent(
            UserProfile userProfile,
            String txmaAuditEncoded,
            AccountDeletionReason reason,
            Subject internalCommonSubjectIdentifier) {
        var auditContext =
                new AuditContext(
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        internalCommonSubjectIdentifier.getValue(),
                        userProfile.getEmail(),
                        AuditService.UNKNOWN,
                        userProfile.getPhoneNumber(),
                        AuditService.UNKNOWN,
                        txmaAuditEncoded);
        return AuthDeleteAccount.create(
                auditContext,
                userProfile.getPublicSubjectID(),
                userProfile.getLegacySubjectID(),
                reason.name(),
                Clock.systemUTC());
    }

    private static AuthDeleteAccount createAuditEvent(
            APIGatewayProxyRequestEvent input,
            UserProfile userProfile,
            String txmaAuditEncoded,
            AccountDeletionReason reason,
            Subject internalCommonSubjectIdentifier) {
        String ipAddress = StructuredAuditService.UNKNOWN;
        String persistentSessionID =
                PersistentIdHelper.extractPersistentIdFromHeaders(input.getHeaders());
        attachLogFieldToLogs(PERSISTENT_SESSION_ID, ipAddress);
        ipAddress = IpAddressHelper.extractIpAddress(input);
        var clientId =
                input.getRequestContext()
                        .getAuthorizer()
                        .getOrDefault("clientId", StructuredAuditService.UNKNOWN)
                        .toString();
        var clientSessionId = ClientSessionIdHelper.extractSessionIdFromHeaders(input.getHeaders());
        var sessionId =
                RequestHeaderHelper.getHeaderValueOrElse(input.getHeaders(), SESSION_ID_HEADER, "");
        var auditContext =
                new AuditContext(
                        clientId,
                        clientSessionId,
                        sessionId,
                        internalCommonSubjectIdentifier.getValue(),
                        userProfile.getEmail(),
                        ipAddress,
                        userProfile.getPhoneNumber(),
                        persistentSessionID,
                        txmaAuditEncoded);
        return AuthDeleteAccount.create(
                auditContext,
                userProfile.getPublicSubjectID(),
                userProfile.getLegacySubjectID(),
                reason.name(),
                Clock.systemUTC());
    }

    private Subject calculateICS(UserProfile userProfile) {
        LOG.info("Calculating internal common subject identifier");
        var internalCommonSubjectIdentifier =
                ClientSubjectHelper.getSubjectWithSectorIdentifier(
                        userProfile,
                        configurationService.getInternalSectorUri(),
                        authenticationService);
        LOG.info("Internal common subject identifier: {}", internalCommonSubjectIdentifier);
        return internalCommonSubjectIdentifier;
    }

    public void deleteAccountViaDataApi(String publicSubjectId, String token) {
        try {
            var response = accountDataApiService.deleteAccount(publicSubjectId, token);
            int statusCode = response.statusCode();
            if (statusCode == 204) {
                LOG.info("Successfully deleted account via Data API");
            } else if (statusCode == 404) {
                LOG.error("Account not found in Data API for publicSubjectId: {}", publicSubjectId);
                throw new RuntimeException(
                        "Account not found in Data API for publicSubjectId: " + publicSubjectId);
            } else {
                LOG.error(
                        "Data API returned error status {} when deleting account for publicSubjectId: {}",
                        statusCode,
                        publicSubjectId);
                throw new RuntimeException(
                        "Data API returned error status " + statusCode + " when deleting account");
            }
        } catch (UnsuccessfulAccountDataApiResponseException e) {
            LOG.error("Failed to call Data API to delete account: {}", e.getMessage());
            throw new RuntimeException("Failed to delete account via Data API", e);
        }
    }
}
