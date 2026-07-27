package uk.gov.di.authentication.accountdata.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.mock;
import static uk.gov.di.authentication.accountdata.helpers.APIGatewayProxyResponseEventMatcher.hasStatus;

class AccountDeleteHandlerTest {

    private final Context context = mock(Context.class);
    private final AccountDeleteHandler handler = new AccountDeleteHandler();

    @Test
    void shouldReturn204() {
        var request = new APIGatewayProxyRequestEvent();

        var result = handler.handleRequest(request, context);

        assertThat(result, hasStatus(204));
    }
}
