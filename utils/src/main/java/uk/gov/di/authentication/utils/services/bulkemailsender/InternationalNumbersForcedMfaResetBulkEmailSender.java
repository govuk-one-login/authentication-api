package uk.gov.di.authentication.utils.services.bulkemailsender;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.shared.entity.BulkEmailStatus;
import uk.gov.di.authentication.shared.entity.BulkEmailUserSendMode;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.BulkEmailUsersService;
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.NotificationService;
import uk.gov.di.authentication.utils.domain.BulkEmailType;
import uk.gov.service.notify.NotificationClientException;

import static uk.gov.di.authentication.shared.entity.NotificationType.INTERNATIONAL_NUMBERS_FORCED_MFA_RESET_BULK_EMAIL;

public class InternationalNumbersForcedMfaResetBulkEmailSender extends BaseBulkEmailSender {

    private static final Logger LOG =
            LogManager.getLogger(InternationalNumbersForcedMfaResetBulkEmailSender.class);

    public InternationalNumbersForcedMfaResetBulkEmailSender(
            BulkEmailUsersService bulkEmailUsersService,
            CloudwatchMetricsService cloudwatchMetricsService,
            ConfigurationService configurationService,
            NotificationService notificationService,
            AuditService auditService,
            DynamoService dynamoService) {
        super(
                bulkEmailUsersService,
                cloudwatchMetricsService,
                configurationService,
                auditService,
                dynamoService,
                notificationService);
    }

    @Override
    public void validateConfiguration() {
        // No-op method as this sender has no configuration that needs validating
    }

    @Override
    public void validateAndSendMessage(String subjectId, BulkEmailUserSendMode sendMode) {
        var userProfileOptional = dynamoService.getOptionalUserProfileFromSubject(subjectId);
        if (userProfileOptional.isEmpty()) {
            LOG.warn("User not found by subject id");
            updateBulkUserStatus(subjectId, BulkEmailStatus.ACCOUNT_NOT_FOUND);
            return;
        }
        var userProfile = userProfileOptional.get();
        var successStatus = sendMode.mapToSuccessStatus();

        try {
            var emailSent =
                    sendEmail(userProfile, INTERNATIONAL_NUMBERS_FORCED_MFA_RESET_BULK_EMAIL);

            if (emailSent) {
                submitAuditEvent(
                        userProfile,
                        sendMode,
                        BulkEmailType.INTERNATIONAL_NUMBERS_FORCED_MFA_RESET_BULK_EMAIL);
            }
            updateBulkUserStatus(subjectId, successStatus);
        } catch (NotificationClientException e) {
            LOG.error("Unable to send bulk email to user: {}", e.getMessage());
            updateBulkUserStatus(subjectId, BulkEmailStatus.ERROR_SENDING_EMAIL);
        }
    }
}
