package uk.gov.di.authentication.shared.services;

import uk.gov.di.authentication.shared.entity.AuthenticationAttempts;
import uk.gov.di.authentication.shared.helpers.NowHelper;

import java.time.Clock;
import java.time.temporal.ChronoUnit;
import java.util.Optional;

public class DynamoAuthenticationAttemptsService extends BaseDynamoService<AuthenticationAttempts> {

    private final NowHelper.NowClock clock;

    public DynamoAuthenticationAttemptsService(ConfigurationService configurationService) {
        super(AuthenticationAttempts.class, "authentication-attempts", configurationService);
        this.clock = new NowHelper.NowClock(Clock.systemUTC());
    }

    public void addCode(String attemptIdentifier) {
        var authenticationAttempt =
                get(attemptIdentifier)
                        .orElse(new AuthenticationAttempts())
                        .withAttemptIdentifier(attemptIdentifier)
                        .withTimeToLive(
                                NowHelper.nowPlus(60, ChronoUnit.SECONDS)
                                        .toInstant()
                                        .getEpochSecond());

        update(authenticationAttempt);
    }

    public void createOrIncrementCount(String attemptIdentifier, long ttl) {

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
                                    .withTimeToLive(ttl));
        }
        update(authenticationAttempt.get());
    }

    public Optional<AuthenticationAttempts> getAuthenticationAttempts(String attemptIdentifier) {
        return get(attemptIdentifier)
                .filter(t -> t.getTimeToLive() > clock.now().toInstant().getEpochSecond());
    }
}
