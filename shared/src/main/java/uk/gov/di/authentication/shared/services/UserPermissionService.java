package uk.gov.di.authentication.shared.services;

import uk.gov.di.authentication.shared.entity.AuthenticationAttempts;
import uk.gov.di.authentication.shared.entity.CountType;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.helpers.NowHelper;

import java.util.Arrays;
import java.util.EnumMap;
import java.util.Map;
import java.util.Optional;

public class UserPermissionService {
    private final BaseDynamoService<AuthenticationAttempts> authenticationAttemptsDynamoService;

    public UserPermissionService(ConfigurationService configurationService) {
        this.authenticationAttemptsDynamoService =
                new BaseDynamoService<>(
                        AuthenticationAttempts.class,
                        "authentication-attempt",
                        configurationService);
    }

    public void createOrIncrementCount(
            String internalSubjectId, long ttl, JourneyType journeyType, CountType countType) {
        Optional<AuthenticationAttempts> authenticationAttempt =
                authenticationAttemptsDynamoService.get(
                        internalSubjectId, buildSortKey(journeyType, countType));
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
        authenticationAttempt.ifPresent(authenticationAttemptsDynamoService::update);
    }

    public int getCount(String internalSubjectId, JourneyType journeyType, CountType countType) {
        long currentTimestamp = NowHelper.now().toInstant().getEpochSecond();
        var authenticationAttemptRecord =
                authenticationAttemptsDynamoService
                        .get(internalSubjectId, buildSortKey(journeyType, countType))
                        .filter(t -> t.getTimeToLive() > currentTimestamp);
        if (authenticationAttemptRecord.isEmpty()) {
            return 0;
        }
        return authenticationAttemptRecord.get().getCount();
    }

    public Map<CountType, Integer> getCountsByJourney(
            String internalSubjectId, JourneyType journeyType) {
        Map<CountType, Integer> results = new EnumMap<>(CountType.class);
        Arrays.stream(CountType.values())
                .forEach(
                        countType -> {
                            var count = getCount(internalSubjectId, journeyType, countType);
                            if (count > 0) {
                                results.put(countType, count);
                            }
                        });
        return results;
    }

    // This should only be used in specific journeys (e.g. reauth) where it's possible that a
    // non-logged in user
    // can go through a journey, and have counts initially stored against a pairwise id
    public Map<CountType, Integer> getCountsByJourneyForSubjectIdAndRpPairwiseId(
            String internalSubjectId, String rpPairwiseId, JourneyType journeyType) {
        Map<CountType, Integer> results = new EnumMap<>(CountType.class);
        Arrays.stream(CountType.values())
                .forEach(
                        countType -> {
                            var count =
                                    getCount(internalSubjectId, journeyType, countType)
                                            + getCount(rpPairwiseId, journeyType, countType);
                            if (count > 0) {
                                results.put(countType, count);
                            }
                        });
        return results;
    }

    public void deleteCount(
            String internalSubjectId, JourneyType journeyType, CountType countType) {
        authenticationAttemptsDynamoService.delete(
                internalSubjectId, buildSortKey(journeyType, countType));
    }

    public static String buildSortKey(JourneyType journeyType, CountType countType) {
        return journeyType.getValue() + "#" + countType.getValue() + "#" + "Count";
    }

    private boolean isTTLExpired(long ttl) {
        return (NowHelper.now().toInstant().getEpochSecond() > ttl);
    }
}
