package uk.gov.di.authentication.utils.services.bulkemailsender;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.entity.BulkEmailStatus;
import uk.gov.di.authentication.shared.entity.BulkEmailUser;
import uk.gov.di.authentication.shared.entity.BulkEmailUserSendMode;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.BulkEmailUsersService;
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.NotificationService;

import java.util.Map;
import java.util.Optional;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class BaseBulkEmailSenderTest {

    private final BulkEmailUsersService bulkEmailUsersService = mock(BulkEmailUsersService.class);
    private final CloudwatchMetricsService cloudwatchMetricsService =
            mock(CloudwatchMetricsService.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final AuditService auditService = mock(AuditService.class);
    private final DynamoService dynamoService = mock(DynamoService.class);
    private final NotificationService notificationService = mock(NotificationService.class);

    static class TestBulkEmailSender extends BaseBulkEmailSender {
        TestBulkEmailSender(
                BulkEmailUsersService bulkEmailUsersService,
                CloudwatchMetricsService cloudwatchMetricsService,
                ConfigurationService configurationService,
                AuditService auditService,
                DynamoService dynamoService,
                NotificationService notificationService) {
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
            // No-op for testing base class
        }

        @Override
        public void validateAndSendMessage(String subjectId, BulkEmailUserSendMode sendMode) {
            // No-op for testing base class
        }
    }

    @Nested
    class UpdateBulkUserStatus {

        @Test
        void shouldUpdateUserStatusAndEmitMetric() {
            when(configurationService.getEnvironment()).thenReturn("test");
            when(bulkEmailUsersService.updateUserStatus("subject-id", BulkEmailStatus.EMAIL_SENT))
                    .thenReturn(Optional.of(new BulkEmailUser()));

            var sender =
                    new TestBulkEmailSender(
                            bulkEmailUsersService,
                            cloudwatchMetricsService,
                            configurationService,
                            auditService,
                            dynamoService,
                            notificationService);

            sender.updateBulkUserStatus("subject-id", BulkEmailStatus.EMAIL_SENT);

            verify(bulkEmailUsersService)
                    .updateUserStatus("subject-id", BulkEmailStatus.EMAIL_SENT);
            verify(cloudwatchMetricsService)
                    .incrementCounter(
                            "BulkEmailStatus",
                            Map.of("Status", "EMAIL_SENT", "Environment", "test"));
        }

        @Test
        void shouldEmitMetricEvenWhenUserNotFound() {
            when(configurationService.getEnvironment()).thenReturn("test");
            when(bulkEmailUsersService.updateUserStatus("subject-id", BulkEmailStatus.EMAIL_SENT))
                    .thenReturn(Optional.empty());

            var sender =
                    new TestBulkEmailSender(
                            bulkEmailUsersService,
                            cloudwatchMetricsService,
                            configurationService,
                            auditService,
                            dynamoService,
                            notificationService);

            sender.updateBulkUserStatus("subject-id", BulkEmailStatus.EMAIL_SENT);

            verify(bulkEmailUsersService)
                    .updateUserStatus("subject-id", BulkEmailStatus.EMAIL_SENT);
            verify(cloudwatchMetricsService)
                    .incrementCounter(
                            "BulkEmailStatus",
                            Map.of("Status", "EMAIL_SENT", "Environment", "test"));
        }
    }
}
