package uk.gov.di.accountmanagement.services;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.accountmanagement.entity.AccountDeletionReason;
import uk.gov.di.accountmanagement.entity.NotificationType;
import uk.gov.di.accountmanagement.entity.NotifyRequest;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.auditevents.entity.AuthDeleteAccount;
import uk.gov.di.authentication.auditevents.services.StructuredAuditService;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.helpers.ClientSessionIdHelper;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.helpers.IpAddressHelper;
import uk.gov.di.authentication.shared.helpers.LocaleHelper;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.helpers.RequestHeaderHelper;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.SerializationService;

import java.time.Clock;
import java.util.Optional;

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
    private final Json objectMapper = SerializationService.getInstance();

    public AccountDeletionService(
            AuthenticationService authenticationService,
            AwsSqsClient sqsClient,
            StructuredAuditService structuredAuditService,
            ConfigurationService configurationService,
            DynamoDeleteService dynamoDeleteService) {
        this.authenticationService = authenticationService;
        this.sqsClient = sqsClient;
        this.structuredAuditService = structuredAuditService;
        this.configurationService = configurationService;
        this.dynamoDeleteService = dynamoDeleteService;
    }

    public void removeAccount(
            Optional<APIGatewayProxyRequestEvent> input,
            UserProfile userProfile,
            String txmaAuditEncoded,
            AccountDeletionReason reason)
            throws Json.JsonException {
        removeAccount(input, userProfile, txmaAuditEncoded, reason, true);
    }

    public void removeAccount(
            Optional<APIGatewayProxyRequestEvent> input,
            UserProfile userProfile,
            String txmaAuditEncoded,
            AccountDeletionReason reason,
            boolean sendNotification)
            throws Json.JsonException {
        LOG.info("Calculating internal common subject identifier");
        var internalCommonSubjectIdentifier =
                ClientSubjectHelper.getSubjectWithSectorIdentifier(
                        userProfile,
                        configurationService.getInternalSectorUri(),
                        authenticationService);
        LOG.info("Internal common subject identifier: {}", internalCommonSubjectIdentifier);
        var email = userProfile.getEmail();

        LOG.info("Deleting user account");
        dynamoDeleteService.deleteAccount(
                email,
                internalCommonSubjectIdentifier.getValue(),
                userProfile.getPublicSubjectID());

        if (sendNotification) {
            try {
                LOG.info("User account removed. Adding notification message to SQS queue");
                NotifyRequest notifyRequest =
                        new NotifyRequest(
                                email,
                                NotificationType.DELETE_ACCOUNT,
                                LocaleHelper.SupportedLanguage.EN);
                sqsClient.send(objectMapper.writeValueAsString((notifyRequest)));
            } catch (Exception e) {
                LOG.error("Failed to send account deletion email: ", e);
            }
        }

        String persistentSessionID = StructuredAuditService.UNKNOWN;
        String ipAddress = StructuredAuditService.UNKNOWN;
        if (input.isPresent()) {
            persistentSessionID =
                    PersistentIdHelper.extractPersistentIdFromHeaders(input.get().getHeaders());
            attachLogFieldToLogs(PERSISTENT_SESSION_ID, ipAddress);
            ipAddress = IpAddressHelper.extractIpAddress(input.get());
        }

        try {
            var clientId =
                    input.map(
                                    n ->
                                            n.getRequestContext()
                                                    .getAuthorizer()
                                                    .getOrDefault(
                                                            "clientId",
                                                            StructuredAuditService.UNKNOWN)
                                                    .toString())
                            .orElse(StructuredAuditService.UNKNOWN);
            var clientSessionId =
                    input.map(
                                    n ->
                                            ClientSessionIdHelper.extractSessionIdFromHeaders(
                                                    n.getHeaders()))
                            .orElse(StructuredAuditService.UNKNOWN);
            var sessionId =
                    input.map(
                                    n ->
                                            RequestHeaderHelper.getHeaderValueOrElse(
                                                    n.getHeaders(), SESSION_ID_HEADER, ""))
                            .orElse(StructuredAuditService.UNKNOWN);
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
            var auditEvent =
                    AuthDeleteAccount.create(
                            auditContext,
                            userProfile.getPublicSubjectID(),
                            userProfile.getLegacySubjectID(),
                            reason.name(),
                            Clock.systemUTC());
            structuredAuditService.submitAuditEvent(auditEvent);
        } catch (Exception e) {
            LOG.error("Failed to audit account deletion: ", e);
        }
    }
}
