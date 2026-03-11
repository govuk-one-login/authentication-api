package uk.gov.di.authentication.utils.services.bulkemailsender;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.entity.BulkEmailStatus;
import uk.gov.di.authentication.shared.entity.BulkEmailUser;
import uk.gov.di.authentication.shared.entity.BulkEmailUserSendMode;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.services.BulkEmailUsersService;
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;
import uk.gov.di.authentication.shared.services.ConfigurationService;

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

    static class TestBulkEmailSender extends BaseBulkEmailSender {
        TestBulkEmailSender(
                BulkEmailUsersService bulkEmailUsersService,
                CloudwatchMetricsService cloudwatchMetricsService,
                ConfigurationService configurationService) {
            super(bulkEmailUsersService, cloudwatchMetricsService, configurationService);
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
                            bulkEmailUsersService, cloudwatchMetricsService, configurationService);

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
                            bulkEmailUsersService, cloudwatchMetricsService, configurationService);

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
