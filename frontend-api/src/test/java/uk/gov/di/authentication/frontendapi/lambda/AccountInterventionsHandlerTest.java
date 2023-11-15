package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;

public class AccountInterventionsHandlerTest {

    @Test
    void shouldReturn200ForSuccessfulRequest() {
        var handler = new AccountInterventionsHandler();
        var context = mock(Context.class);
        var event = new APIGatewayProxyRequestEvent();

        var result = handler.handleRequest(event, context);
        assertEquals(200, result.getStatusCode());
        assertEquals("Hello world", result.getBody());
    }
}
