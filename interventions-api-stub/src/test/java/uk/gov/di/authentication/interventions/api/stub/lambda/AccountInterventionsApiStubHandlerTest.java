package uk.gov.di.authentication.interventions.api.stub.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.interventions.api.stub.entity.AccountInterventionsStore;
import uk.gov.di.authentication.interventions.api.stub.services.AccountInterventionsDbService;

import java.util.Map;
import java.util.Optional;

import static java.lang.String.format;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AccountInterventionsApiStubHandlerTest {

    private final AccountInterventionsDbService accountInterventionsDbService =
            mock(AccountInterventionsDbService.class);

    private static final String PATH_PARAM_NAME_IN_API_GW = "internalPairwiseId";

    private static final String PAIRWISE_ID = "testPairwiseId";
    private static Context context = mock(Context.class);

    private static AccountInterventionsStore accountInterventionsStore =
            new AccountInterventionsStore()
                    .withPairwiseId(PAIRWISE_ID)
                    .withBlocked(true)
                    .withSuspended(true)
                    .withResetPassword(true)
                    .withReproveIdentity(true);

    @Test
    void shouldReturn200ForSuccessfulRequest() {
        var handler = new AccountInterventionsApiStubHandler(accountInterventionsDbService);
        when(accountInterventionsDbService.getAccountInterventions(PAIRWISE_ID))
                .thenReturn(Optional.of(accountInterventionsStore));

        var event = new APIGatewayProxyRequestEvent();
        event.setPathParameters(Map.of(PATH_PARAM_NAME_IN_API_GW, PAIRWISE_ID));

        var result = handler.handleRequest(event, context);
        assertEquals(200, result.getStatusCode());
        var interventionBlock =
                "{\"blocked\":true,\"resetPassword\":true,\"suspended\":true,\"reproveIdentity\":true}";
        var stateBlock =
                "{\"updatedAt\":1696969322935,\"appliedAt\":1696869005821,\"sentAt\":1696869003456,\"description\":\"AIS_USER_PASSWORD_RESET_AND_IDENTITY_VERIFIED\",\"reprovedIdentityAt\":1696969322935,\"resetPasswordAt\":1696875903456}";
        var expectedJson =
                format("{\"intervention\":%s,\"state\":%s}", interventionBlock, stateBlock);
        assertEquals(expectedJson, result.getBody());
    }

    @Test
    void shouldReturn404WhenThePairwiseIdDoesNotExistInTheDatabase() {
        var handler = new AccountInterventionsApiStubHandler(accountInterventionsDbService);
        when(accountInterventionsDbService.getAccountInterventions(PAIRWISE_ID))
                .thenReturn(Optional.empty());

        var event = new APIGatewayProxyRequestEvent();
        event.setPathParameters(Map.of(PATH_PARAM_NAME_IN_API_GW, PAIRWISE_ID));

        var result = handler.handleRequest(event, context);
        assertEquals(404, result.getStatusCode());
    }
}
