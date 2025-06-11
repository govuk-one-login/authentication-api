package uk.gov.di.authentication.shared.helpers;

import uk.gov.di.authentication.shared.entity.CountType;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.util.List;
import java.util.Map;

import static uk.gov.di.authentication.shared.entity.CountType.ENTER_EMAIL;
import static uk.gov.di.authentication.shared.entity.CountType.ENTER_MFA_CODE;
import static uk.gov.di.authentication.shared.entity.CountType.ENTER_PASSWORD;

public class ReauthAuthenticationAttemptsHelper {

    private ReauthAuthenticationAttemptsHelper() {}

    public static List<CountType> countTypesWhereUserIsBlockedForReauth(
            Map<CountType, Integer> retrievedCountTypesToCounts,
            ConfigurationService configurationService) {
        var reauthRelevantCountsToMaxRetries =
                Map.ofEntries(
                        Map.entry(ENTER_EMAIL, configurationService.getMaxEmailReAuthRetries()),
                        Map.entry(ENTER_PASSWORD, configurationService.getMaxPasswordRetries()),
                        Map.entry(ENTER_MFA_CODE, configurationService.getCodeMaxRetries()));

        return reauthRelevantCountsToMaxRetries.entrySet().stream()
                .filter(
                        entry -> {
                            var countType = entry.getKey();
                            var maxValue = entry.getValue();
                            return retrievedCountTypesToCounts.containsKey(countType)
                                    && retrievedCountTypesToCounts.get(countType) >= maxValue;
                        })
                .map(Map.Entry::getKey)
                .toList();
    }
}
