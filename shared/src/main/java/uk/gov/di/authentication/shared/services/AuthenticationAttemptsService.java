package uk.gov.di.authentication.shared.services;

import uk.gov.di.authentication.shared.entity.AuthenticationAttempts;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.helpers.NowHelper;

import java.time.temporal.ChronoUnit;
import java.util.Optional;

public class AuthenticationAttemptsService extends BaseDynamoService<AuthenticationAttempts> {

    public AuthenticationAttemptsService(ConfigurationService configurationService) {
        super(AuthenticationAttempts.class, "authentication-attempt", configurationService);
    }

    public void incrementCount(String internalSubjectId, JourneyType journey, String credentialType) {
        // creates new record or increments an existing one
        // Use the updateItem method with an update expression such as:
        // SET count = if_not_exists(count, :start) + :inc, ...
        // this will either update an existing record or it will create a new record with the count set to :start
    }

    public int getAttemptCount(String internalSubjectId, JourneyType journey, String credentialType) {
        String pk = internalSubjectId;
        String sortKey = journey + "#" + credentialType + "#Count";

        return get(pk, sortKey).get().getCount();
    }

    public void setLastEnteredCredential(String internalSubjectId, JourneyType journey, String credentialType, String credentialValue) {
        // creates new record or updates an existing one
    }

    public String getLastEnteredCredential(String internalSubjectId, JourneyType journey, String credentialType) {
        return "";
    }

    public void addCode(
            String internalSubjectId,
            long ttlSeconds,
            String code,
            String authenticationMethod,
            String journeyType) {
        long ttlEpochSeconds =
                NowHelper.nowPlus(ttlSeconds, ChronoUnit.SECONDS).toInstant().getEpochSecond();

        Optional<AuthenticationAttempts> authenticationAttempt =
                get(internalSubjectId, buildSortKey(authenticationMethod, journeyType));
        if (authenticationAttempt.isPresent()) {
            authenticationAttempt.get().setCount(authenticationAttempt.get().getCount() + 1);
            authenticationAttempt.get().setTimeToLive(ttlEpochSeconds);
        } else {
            authenticationAttempt =
                    Optional.ofNullable(
                            new AuthenticationAttempts()
                                    .withInternalSubjectId(internalSubjectId)
                                    .withAuthenticationMethod(authenticationMethod)
                                    .withJourneyType(journeyType)
                                    .withCode(code)
                                    .withTimeToLive(ttlEpochSeconds));
        }
        authenticationAttempt.ifPresent(this::update);
    }

    public void createOrIncrementCount(
            String internalSubjectId, long ttl, String authenticationMethod, String journeyType) {
        Optional<AuthenticationAttempts> authenticationAttempt =
                get(internalSubjectId, buildSortKey(authenticationMethod, journeyType));
        if (authenticationAttempt.isPresent()) {
            authenticationAttempt.get().setCount(authenticationAttempt.get().getCount() + 1);
            authenticationAttempt.get().setTimeToLive(ttl);
        } else {
            authenticationAttempt =
                    Optional.ofNullable(
                            new AuthenticationAttempts()
                                    .withInternalSubjectId(internalSubjectId)
                                    .withCount(1)
                                    .withAuthenticationMethod(authenticationMethod)
                                    .withJourneyType(journeyType)
                                    .withTimeToLive(ttl));
        }
        authenticationAttempt.ifPresent(this::update);
    }

    public Optional<AuthenticationAttempts> getAuthenticationAttempt(
            String internalSubjectId, String authenticationMethod, String journeyType) {
        long currentTimestamp = NowHelper.now().toInstant().getEpochSecond();
        return get(internalSubjectId, buildSortKey(authenticationMethod, journeyType))
                .filter(t -> t.getTimeToLive() > currentTimestamp);
    }

    public Optional<String> getCode(
            String internalSubjectId, String authenticationMethod, String journeyType) {
        return get(internalSubjectId, buildSortKey(authenticationMethod, journeyType))
                .map(AuthenticationAttempts::getCode);
    }

    public void deleteCount(
            String internalSubjectId, String authenticationMethod, String journeyType) {
        Optional<AuthenticationAttempts> attempt =
                get(internalSubjectId, buildSortKey(authenticationMethod, journeyType));
        attempt.ifPresent(
                authAttempt -> {
                    authAttempt.setCount(0);
                    update(authAttempt);
                });
    }

    public void deleteCode(
            String internalSubjectId, String authenticationMethod, String journeyType) {
        Optional<AuthenticationAttempts> attempt =
                get(internalSubjectId, buildSortKey(authenticationMethod, journeyType));
        attempt.ifPresent(
                authAttempt -> {
                    authAttempt.setCode(null);
                    update(authAttempt);
                });
    }

    public static String buildSortKey(String authenticationMethod, String journeyType) {
        return authenticationMethod + "_" + journeyType;
    }
}
