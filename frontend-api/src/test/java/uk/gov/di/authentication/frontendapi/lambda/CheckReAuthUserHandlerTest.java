package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;

class CheckReAuthUserHandlerTest {
    @Test
    void shouldReturn200ForSuccessfulRequest() {
        var handler = new CheckReAuthUserHandler();
        var context = mock(Context.class);
        var event = new APIGatewayProxyRequestEvent();

        var result = handler.handleRequest(event, context);
        assertEquals(200, result.getStatusCode());
        assertEquals("Hello world", result.getBody());
    }
}
