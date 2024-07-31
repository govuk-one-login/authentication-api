package uk.gov.di.authentication.shared.services;

import uk.gov.di.authentication.shared.entity.AuthenticationAttempts;
import uk.gov.di.authentication.shared.helpers.NowHelper;

import java.time.temporal.ChronoUnit;
import java.util.Optional;

public class DynamoAuthenticationAttemptsService extends BaseDynamoService<AuthenticationAttempts> {

    public DynamoAuthenticationAttemptsService(ConfigurationService configurationService) {
        super(AuthenticationAttempts.class, "authentication-attempts", configurationService);
    }

    public void addCode(
            String attemptIdentifier, long ttlSeconds, String code, String authenticationMethod) {
        long ttlEpochSeconds =
                NowHelper.nowPlus(ttlSeconds, ChronoUnit.SECONDS).toInstant().getEpochSecond();

        var authenticationAttempt =
                get(attemptIdentifier)
                        .orElse(new AuthenticationAttempts())
                        .withAttemptIdentifier(attemptIdentifier)
                        .withCode(code)
                        .withAuthenticationMethod(authenticationMethod)
                        .withTimeToLive(ttlEpochSeconds);

        update(authenticationAttempt);
    }

    public void createOrIncrementCount(
            String attemptIdentifier, long ttl, String authenticationMethod) {
        Optional<AuthenticationAttempts> authenticationAttempt = get(attemptIdentifier);
        if (authenticationAttempt.isPresent()) {
            authenticationAttempt.get().setCount(authenticationAttempt.get().getCount() + 1);
            authenticationAttempt.get().setTimeToLive(ttl);
        } else {
            authenticationAttempt =
                    Optional.ofNullable(
                            new AuthenticationAttempts()
                                    .withAttemptIdentifier(attemptIdentifier)
                                    .withCount(1)
                                    .withAuthenticationMethod(authenticationMethod)
                                    .withTimeToLive(ttl));
        }
        authenticationAttempt.ifPresent(this::update);
    }

    public Optional<AuthenticationAttempts> getAuthenticationAttempts(String attemptIdentifier) {
        long currentTimestamp = NowHelper.now().toInstant().getEpochSecond();
        return get(attemptIdentifier).filter(t -> t.getTimeToLive() > currentTimestamp);
    }

    public Optional<String> getCode(String attemptIdentifier) {
        return get(attemptIdentifier).map(AuthenticationAttempts::getCode);
    }

    public void deleteCount(String attemptIdentifier) {
        Optional<AuthenticationAttempts> attempt = get(attemptIdentifier);
        attempt.ifPresent(
                authAttempt -> {
                    authAttempt.setCount(0);
                    update(authAttempt);
                });
    }

    public void deleteCode(String attemptIdentifier) {
        Optional<AuthenticationAttempts> attempt = get(attemptIdentifier);
        attempt.ifPresent(
                authAttempt -> {
                    authAttempt.setCode(null);
                    update(authAttempt);
                });
    }
}
