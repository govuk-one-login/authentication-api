package uk.gov.di.authentication.utils.services.bulkemailsender;

import uk.gov.di.authentication.shared.entity.BulkEmailUserSendMode;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.BulkEmailUsersService;
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.NotificationService;

public class InternationalNumbersForcedMfaResetBulkEmailSender extends BaseBulkEmailSender {

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
    public void validateAndSendMessage(String subjectId, BulkEmailUserSendMode sendMode) {}
}
