package uk.gov.di.authentication.utils.services.bulkemailsender;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.shared.entity.BulkEmailStatus;
import uk.gov.di.authentication.shared.entity.BulkEmailUserSendMode;
import uk.gov.di.authentication.shared.entity.NotificationType;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.BulkEmailUsersService;
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.NotificationService;
import uk.gov.di.authentication.utils.domain.BulkEmailType;
import uk.gov.di.authentication.utils.domain.UtilsAuditableEvent;
import uk.gov.service.notify.NotificationClientException;

import java.util.Map;

import static uk.gov.di.audit.AuditContext.emptyAuditContext;
import static uk.gov.di.authentication.shared.services.AuditService.MetadataPair.pair;

public abstract class BaseBulkEmailSender implements BulkEmailSender {

    private static final Logger LOG = LogManager.getLogger(BaseBulkEmailSender.class);

    protected final BulkEmailUsersService bulkEmailUsersService;
    protected final CloudwatchMetricsService cloudwatchMetricsService;
    protected final ConfigurationService configurationService;
    protected final AuditService auditService;
    protected final DynamoService dynamoService;
    protected final NotificationService notificationService;

    protected BaseBulkEmailSender(
            BulkEmailUsersService bulkEmailUsersService,
            CloudwatchMetricsService cloudwatchMetricsService,
            ConfigurationService configurationService,
            AuditService auditService,
            DynamoService dynamoService,
            NotificationService notificationService) {
        this.bulkEmailUsersService = bulkEmailUsersService;
        this.cloudwatchMetricsService = cloudwatchMetricsService;
        this.configurationService = configurationService;
        this.auditService = auditService;
        this.dynamoService = dynamoService;
        this.notificationService = notificationService;
    }

    @Override
    public void updateBulkUserStatus(String subjectId, BulkEmailStatus bulkEmailStatus) {
        if (bulkEmailUsersService.updateUserStatus(subjectId, bulkEmailStatus).isPresent()) {
            LOG.info("Bulk email user status updated to: {}", bulkEmailStatus.getValue());
        } else {
            LOG.warn("Bulk user email status not updated, user not found.");
        }
        cloudwatchMetricsService.incrementCounter(
                "BulkEmailStatus",
                Map.of(
                        "Status",
                        bulkEmailStatus.getValue(),
                        "Environment",
                        configurationService.getEnvironment()));
    }

    protected void submitAuditEvent(
            UserProfile userProfile, BulkEmailUserSendMode sendMode, BulkEmailType bulkEmailType) {
        var auditableEvent =
                BulkEmailUserSendMode.DELIVERY_RECEIPT_TEMPORARY_FAILURE_RETRIES.equals(sendMode)
                        ? UtilsAuditableEvent.AUTH_BULK_RETRY_EMAIL_SENT
                        : UtilsAuditableEvent.AUTH_BULK_EMAIL_SENT;
        var internalCommonSubjectIdentifier =
                userProfile.getSalt() != null
                        ? ClientSubjectHelper.getSubjectWithSectorIdentifier(
                                        userProfile,
                                        configurationService.getInternalSectorUri(),
                                        dynamoService)
                                .getValue()
                        : AuditService.UNKNOWN;
        auditService.submitAuditEvent(
                auditableEvent,
                emptyAuditContext()
                        .withEmail(userProfile.getEmail())
                        .withSubjectId(internalCommonSubjectIdentifier),
                pair("internalSubjectId", userProfile.getSubjectID()),
                pair("bulk-email-type", bulkEmailType.name()));
    }

    protected boolean sendEmail(UserProfile userProfile, NotificationType template)
            throws NotificationClientException {
        if (configurationService.isBulkUserEmailEmailSendingEnabled()) {
            LOG.info("Bulk user email sending email.");
            notificationService.sendEmail(userProfile.getEmail(), Map.of(), template, "");
            return true;
        } else {
            LOG.info("Bulk user email email sending not enabled.");
            return false;
        }
    }
}
