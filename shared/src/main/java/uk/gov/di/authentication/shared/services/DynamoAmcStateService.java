package uk.gov.di.authentication.shared.services;

import uk.gov.di.authentication.shared.entity.AMCState;
import uk.gov.di.authentication.shared.helpers.NowHelper;

import java.time.temporal.ChronoUnit;

public class DynamoAmcStateService extends BaseDynamoService<AMCState> {
    public DynamoAmcStateService(ConfigurationService configurationService) {
        super(AMCState.class, "amc-state", configurationService);
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
}
