package uk.gov.di.authentication.shared.services;

import uk.gov.di.authentication.shared.entity.AMCState;
import uk.gov.di.authentication.shared.helpers.NowHelper;

import java.time.Clock;
import java.time.temporal.ChronoUnit;
import java.util.Optional;

public class DynamoAmcStateService extends BaseDynamoService<AMCState> {
    private final Clock clock;

    public DynamoAmcStateService(ConfigurationService configurationService) {
        super(AMCState.class, "amc-state", configurationService);
        this.clock = Clock.systemUTC();
    }

    public DynamoAmcStateService(ConfigurationService configurationService, Clock clock) {
        super(AMCState.class, "amc-state", configurationService);
        this.clock = clock;
    }

    public void store(String authenticationState, String clientSessionId) {
        long timeToExist = NowHelper.nowPlus(2L, ChronoUnit.HOURS).toInstant().getEpochSecond();
        AMCState amcState =
                new AMCState()
                        .withAuthenticationState(authenticationState)
                        .withClientSessionId(clientSessionId)
                        .withTimeToExist(timeToExist);
        put(amcState);
    }

    public Optional<AMCState> getNonExpiredState(String authenticationState) {
        var maybeState = get(authenticationState);
        var now = clock.instant().getEpochSecond();
        return maybeState.filter(amcState -> amcState.getTimeToExist() > now);
    }
}
