package uk.gov.di.authentication.shared.services;

import uk.gov.di.authentication.shared.entity.AuthenticationAttempts;
import uk.gov.di.authentication.shared.entity.CountType;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.helpers.NowHelper;

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
        return authenticationAttemptRecord.get().getCount();
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
