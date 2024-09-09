package uk.gov.di.authentication.shared.helpers;

import uk.gov.di.authentication.shared.entity.CountType;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.services.AuthenticationAttemptsService;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.util.List;
import java.util.Map;

import static uk.gov.di.authentication.shared.entity.CountType.ENTER_AUTH_APP_CODE;
import static uk.gov.di.authentication.shared.entity.CountType.ENTER_EMAIL;
import static uk.gov.di.authentication.shared.entity.CountType.ENTER_PASSWORD;
import static uk.gov.di.authentication.shared.entity.CountType.ENTER_SMS_CODE;

public class ReauthAuthenticationAttemptsHelper {
    private AuthenticationAttemptsService authenticationAttemptsService;
    private ConfigurationService configurationService;
    private static final JourneyType JOURNEY_TYPE = JourneyType.REAUTHENTICATION;

    public ReauthAuthenticationAttemptsHelper(
            ConfigurationService configurationService,
            AuthenticationAttemptsService authenticationAttemptsService) {
        this.configurationService = configurationService;
        this.authenticationAttemptsService = authenticationAttemptsService;
    }

    public boolean isBlockedForReauth(String internalSubjectId) {
        return reauthRelevantCountsToMaxRetries().entrySet().stream()
                .anyMatch(
                        entry ->
                                authenticationAttemptsService.getCount(
                                                internalSubjectId, JOURNEY_TYPE, entry.getKey())
                                        >= entry.getValue());
    }

    public List<CountType> countTypesWhereUserIsBlockedForReauth(
            Map<CountType, Integer> retrievedCountTypesToCounts) {
        return reauthRelevantCountsToMaxRetries().entrySet().stream()
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

    private Map<CountType, Integer> reauthRelevantCountsToMaxRetries() {
        return Map.ofEntries(
                Map.entry(ENTER_EMAIL, configurationService.getMaxEmailReAuthRetries()),
                Map.entry(ENTER_PASSWORD, configurationService.getMaxPasswordRetries()),
                Map.entry(ENTER_SMS_CODE, configurationService.getCodeMaxRetries()),
                Map.entry(ENTER_AUTH_APP_CODE, configurationService.getCodeMaxRetries()));
    }
}
