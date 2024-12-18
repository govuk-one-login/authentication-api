package uk.gov.di.authentication.shared.services;

import uk.gov.di.authentication.shared.entity.IDReverificationState;
import uk.gov.di.authentication.shared.helpers.NowHelper;

import java.time.temporal.ChronoUnit;

public class IDReverificationStateService extends BaseDynamoService<IDReverificationState> {
    public IDReverificationStateService(ConfigurationService configurationService) {
        super(IDReverificationState.class, "id-reverification-state", configurationService);
    }

    public void store(
            String authenticationState, String orchestrationRedirectUrl, String clientSessionId) {
        long timeToExist = NowHelper.nowPlus(2L, ChronoUnit.HOURS).toInstant().getEpochSecond();
        IDReverificationState idReverificationState =
                new IDReverificationState()
                        .withAuthenticationState(authenticationState)
                        .withOrchestrationRedirectUrl(orchestrationRedirectUrl)
                        .withClientSessionId(clientSessionId)
                        .withTimeToExist(timeToExist);
        put(idReverificationState);
    }
}
