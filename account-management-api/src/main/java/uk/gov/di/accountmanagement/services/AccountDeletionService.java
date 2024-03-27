package uk.gov.di.accountmanagement.services;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.accountmanagement.domain.AccountManagementAuditableEvent;
import uk.gov.di.accountmanagement.entity.NotificationType;
import uk.gov.di.accountmanagement.entity.NotifyRequest;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.helpers.LocaleHelper;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.SerializationService;

public class AccountDeletionService {
    private static final Logger LOG = LogManager.getLogger(AccountDeletionService.class);

    private final AuthenticationService authenticationService;
    private final AwsSqsClient sqsClient;
    private final AuditService auditService;
    private final ConfigurationService configurationService;
    private final DynamoDeleteService dynamoDeleteService;
    private final Json objectMapper = SerializationService.getInstance();

    public AccountDeletionService(
            AuthenticationService authenticationService,
            AwsSqsClient sqsClient,
            AuditService auditService,
            ConfigurationService configurationService,
            DynamoDeleteService dynamoDeleteService) {
        this.authenticationService = authenticationService;
        this.sqsClient = sqsClient;
        this.auditService = auditService;
        this.configurationService = configurationService;
        this.dynamoDeleteService = dynamoDeleteService;
    }

    public DeletedAccountIdentifiers removeAccount(UserProfile userProfile)
            throws Json.JsonException {
        var accountIdentifiers =
                new DeletedAccountIdentifiers(
                        userProfile.getPublicSubjectID(),
                        userProfile.getLegacySubjectID(),
                        userProfile.getSubjectID());

        LOG.info("Calculating internal common subject identifier");
        var internalCommonSubjectIdentifier =
                ClientSubjectHelper.getSubjectWithSectorIdentifier(
                        userProfile,
                        configurationService.getInternalSectorUri(),
                        authenticationService);
        LOG.info("Internal common subject identifier: {}", internalCommonSubjectIdentifier);
        var email = userProfile.getEmail();

        LOG.info("Deleting user account");
        dynamoDeleteService.deleteAccount(email, internalCommonSubjectIdentifier.getValue());

        try {
            LOG.info("User account removed. Adding message to SQS queue");
            NotifyRequest notifyRequest =
                    new NotifyRequest(
                            email,
                            NotificationType.DELETE_ACCOUNT,
                            LocaleHelper.SupportedLanguage.EN);
            sqsClient.send(objectMapper.writeValueAsString((notifyRequest)));
        } catch (Exception e) {
            LOG.error("Failed to send account deletion email: ", e);
        }

        try {
            auditService.submitAuditEvent(
                    AccountManagementAuditableEvent.DELETE_ACCOUNT,
                    AuditService.UNKNOWN,
                    AuditService.UNKNOWN,
                    AuditService.UNKNOWN,
                    internalCommonSubjectIdentifier.getValue(),
                    userProfile.getEmail(),
                    AuditService.UNKNOWN,
                    userProfile.getPhoneNumber(),
                    AuditService.UNKNOWN);
        } catch (Exception e) {
            LOG.error("Failed to audit account deletion: ", e);
        }
        return accountIdentifiers;
    }

    public record DeletedAccountIdentifiers(
            String publicSubjectId, String legacySubjectId, String subjectId) {}
}
