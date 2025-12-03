package uk.gov.di.authentication.shared.services;

import uk.gov.di.authentication.shared.entity.AuthenticationAttempts;
import uk.gov.di.authentication.shared.entity.CountType;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.helpers.NowHelper;

import java.util.Arrays;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

public class AuthenticationAttemptsService extends BaseDynamoService<AuthenticationAttempts> {
    public AuthenticationAttemptsService(ConfigurationService configurationService) {
        super(AuthenticationAttempts.class, "authentication-attempt", configurationService);
    }

    public void createOrIncrementCount(
            String internalSubjectId, long ttl, JourneyType journeyType, CountType countType) {
        Optional<AuthenticationAttempts> authenticationAttempt =
                get(internalSubjectId, buildSortKey(journeyType, countType));
        if (authenticationAttempt.isPresent()) {
            if (isTTLExpired(authenticationAttempt.get().getTimeToLive())) {
                authenticationAttempt.get().setTimeToLive(ttl);
                authenticationAttempt.get().setCount(1);
            } else {
                authenticationAttempt.get().setCount(authenticationAttempt.get().getCount() + 1);
            }

        } else {
            authenticationAttempt =
                    Optional.ofNullable(
                            new AuthenticationAttempts()
                                    .withInternalSubjectId(internalSubjectId)
                                    .withCount(1)
                                    .withCountType(countType)
                                    .withJourneyType(journeyType)
                                    .withTimeToLive(ttl));
        }
        authenticationAttempt.ifPresent(this::update);
    }

    public int getCount(String internalSubjectId, JourneyType journeyType, CountType countType) {
        long currentTimestamp = NowHelper.now().toInstant().getEpochSecond();
        var authenticationAttemptRecord =
                get(internalSubjectId, buildSortKey(journeyType, countType))
                        .filter(t -> t.getTimeToLive() > currentTimestamp);
        if (authenticationAttemptRecord.isEmpty()) {
            return 0;
        }

        int count = authenticationAttemptRecord.get().getCount();

        // TODO remove temporary ZDD measure to sum deprecated count types
        if (countType.equals(CountType.ENTER_MFA_CODE)) {
            count +=
                    get(internalSubjectId, buildSortKey(journeyType, CountType.ENTER_SMS_CODE))
                                    .filter(t -> t.getTimeToLive() > currentTimestamp)
                                    .map(AuthenticationAttempts::getCount)
                                    .orElse(0)
                            + get(
                                            internalSubjectId,
                                            buildSortKey(
                                                    journeyType, CountType.ENTER_AUTH_APP_CODE))
                                    .filter(t -> t.getTimeToLive() > currentTimestamp)
                                    .map(AuthenticationAttempts::getCount)
                                    .orElse(0);
        }

        return count;
    }

    public Map<CountType, Integer> getCountsByJourneyForIdentifiers(
            List<String> identifiers, JourneyType journeyType) {
        Map<CountType, Integer> results = new EnumMap<>(CountType.class);
        var identifierList = identifiers.stream().filter(Objects::nonNull).distinct().toList();
        Arrays.stream(CountType.values())
                // TODO remove temporary ZDD measure to sum deprecated count types
                .filter(t -> t != CountType.ENTER_SMS_CODE && t != CountType.ENTER_AUTH_APP_CODE)
                .forEach(
                        countType -> {
                            var count =
                                    identifierList.stream()
                                            .mapToInt(
                                                    identifier ->
                                                            getCount(
                                                                    identifier,
                                                                    journeyType,
                                                                    countType))
                                            .sum();
                            if (count > 0) {
                                results.put(countType, count);
                            }
                        });

        return results;
    }

    public Map<CountType, Integer> getCountsByJourney(
            String internalSubjectId, JourneyType journeyType) {
        return getCountsByJourneyForIdentifiers(Arrays.asList(internalSubjectId), journeyType);
    }

    // This should only be used in specific journeys (e.g. reauth) where it's possible that a
    // non-logged in user
    // can go through a journey, and have counts initially stored against a pairwise id
    public Map<CountType, Integer> getCountsByJourneyForSubjectIdAndRpPairwiseId(
            String internalSubjectId, String rpPairwiseId, JourneyType journeyType) {
        return getCountsByJourneyForIdentifiers(
                Arrays.asList(internalSubjectId, rpPairwiseId), journeyType);
    }

    public void deleteCount(
            String internalSubjectId, JourneyType journeyType, CountType countType) {
        delete(internalSubjectId, buildSortKey(journeyType, countType));
    }

    public static String buildSortKey(JourneyType journeyType, CountType countType) {
        return journeyType.getValue() + "#" + countType.getValue() + "#" + "Count";
    }

    private boolean isTTLExpired(long ttl) {
        return (NowHelper.now().toInstant().getEpochSecond() > ttl);
    }
}
