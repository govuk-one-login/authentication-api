package uk.gov.di.authentication.shared.helpers;

import uk.gov.di.authentication.shared.entity.CountType;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.util.List;
import java.util.Map;

import static uk.gov.di.authentication.shared.entity.CountType.ENTER_AUTH_APP_CODE;
import static uk.gov.di.authentication.shared.entity.CountType.ENTER_EMAIL;
import static uk.gov.di.authentication.shared.entity.CountType.ENTER_PASSWORD;
import static uk.gov.di.authentication.shared.entity.CountType.ENTER_SMS_CODE;

public class ReauthAuthenticationAttemptsHelper {
    private ConfigurationService configurationService;

    public ReauthAuthenticationAttemptsHelper(ConfigurationService configurationService) {
        this.configurationService = configurationService;
    }

    public List<CountType> countTypesWhereUserIsBlockedForReauth(
            Map<CountType, Integer> retrievedCountTypesToCounts) {
        var reauthRelevantCountsToMaxRetries =
                Map.ofEntries(
                        Map.entry(ENTER_EMAIL, configurationService.getMaxEmailReAuthRetries()),
                        Map.entry(ENTER_PASSWORD, configurationService.getMaxPasswordRetries()),
                        Map.entry(ENTER_SMS_CODE, configurationService.getCodeMaxRetries()),
                        Map.entry(ENTER_AUTH_APP_CODE, configurationService.getCodeMaxRetries()));

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
