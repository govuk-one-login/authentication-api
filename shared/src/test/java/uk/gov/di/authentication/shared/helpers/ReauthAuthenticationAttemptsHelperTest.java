package uk.gov.di.authentication.shared.helpers;

import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.entity.CountType;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ReauthAuthenticationAttemptsHelperTest {
    private final ConfigurationService configurationService = mock(ConfigurationService.class);

    @Test
    void countTypesThatExceedMaxShouldReturnTheCountTypesThatHaveExceededTheirMaximums() {
        var maxEmailRetries = 5;
        var maxPasswordRetries = 6;
        var maxCodeRetries = 4;

        when(configurationService.getCodeMaxRetries()).thenReturn(maxCodeRetries);
        when(configurationService.getMaxEmailReAuthRetries()).thenReturn(maxEmailRetries);
        when(configurationService.getMaxPasswordRetries()).thenReturn(maxPasswordRetries);

        var retrievedCountTypesToCounts =
                Map.ofEntries(
                        Map.entry(CountType.ENTER_EMAIL, maxEmailRetries + 1),
                        Map.entry(CountType.ENTER_PASSWORD, maxPasswordRetries - 1),
                        Map.entry(CountType.ENTER_MFA_CODE, maxCodeRetries),
                        Map.entry(CountType.ENTER_EMAIL_CODE, 100));

        var expectedReauthCountsExceeded =
                List.of(
                        CountType.ENTER_EMAIL,
                        CountType.ENTER_MFA_CODE,
                        CountType.ENTER_EMAIL_CODE);
        var actualReauthCountsExceeded =
                ReauthAuthenticationAttemptsHelper.countTypesWhereUserIsBlockedForReauth(
                        retrievedCountTypesToCounts, configurationService);

        assertTrue(
                expectedReauthCountsExceeded.containsAll(actualReauthCountsExceeded)
                        && actualReauthCountsExceeded.containsAll(expectedReauthCountsExceeded));
    }
}
