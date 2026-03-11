package uk.gov.di.authentication.utils.services.bulkemailsender;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.entity.BulkEmailStatus;
import uk.gov.di.authentication.shared.entity.TermsAndConditions;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.services.BulkEmailUsersService;
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class TermsAndConditionsBulkEmailSenderTest {

    private final BulkEmailUsersService bulkEmailUsersService = mock(BulkEmailUsersService.class);
    private final CloudwatchMetricsService cloudwatchMetricsService =
            mock(CloudwatchMetricsService.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);

    @Nested
    class ValidateUser {

        @Test
        void shouldReturnTrueWhenUserHasNoTermsAndConditions() {
            when(configurationService.getBulkUserEmailIncludedTermsAndConditions())
                    .thenReturn(List.of("1.0", "1.1"));

            var sender =
                    new TermsAndConditionsBulkEmailSender(
                            bulkEmailUsersService, cloudwatchMetricsService, configurationService);

            var userProfile = new UserProfile();

            assertTrue(sender.validateUser(userProfile));
        }

        @Test
        void shouldReturnTrueWhenUserTermsAndConditionsVersionIsInIncludedList() {
            when(configurationService.getBulkUserEmailIncludedTermsAndConditions())
                    .thenReturn(List.of("1.0", "1.1"));

            var sender =
                    new TermsAndConditionsBulkEmailSender(
                            bulkEmailUsersService, cloudwatchMetricsService, configurationService);

            var userProfile =
                    new UserProfile()
                            .withTermsAndConditions(new TermsAndConditions("1.0", "2024-01-01"));

            assertTrue(sender.validateUser(userProfile));
        }

        @Test
        void shouldReturnFalseWhenUserTermsAndConditionsVersionIsNotInIncludedList() {
            when(configurationService.getBulkUserEmailIncludedTermsAndConditions())
                    .thenReturn(List.of("1.0", "1.1"));
            when(configurationService.getEnvironment()).thenReturn("test");

            var sender =
                    new TermsAndConditionsBulkEmailSender(
                            bulkEmailUsersService, cloudwatchMetricsService, configurationService);

            var userProfile =
                    new UserProfile()
                            .withSubjectID("subject-id")
                            .withTermsAndConditions(new TermsAndConditions("1.5", "2024-01-01"));

            assertFalse(sender.validateUser(userProfile));
            verify(bulkEmailUsersService)
                    .updateUserStatus("subject-id", BulkEmailStatus.TERMS_ACCEPTED_RECENTLY);
        }
    }
}
