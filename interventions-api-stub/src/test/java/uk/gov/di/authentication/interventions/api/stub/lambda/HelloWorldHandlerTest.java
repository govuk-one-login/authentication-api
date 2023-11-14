package uk.gov.di.authentication.interventions.api.stub.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;

class HelloWorldHandlerTest {

    @Test
    void shouldReturn200ForSuccessfulRequest() {
        var handler = new HelloWorldHandler();
        var context = mock(Context.class);
        var event = new APIGatewayProxyRequestEvent();

        var result = handler.handleRequest(event, context);
        assertEquals(200, result.getStatusCode());
        assertEquals("Hello world", result.getBody());
    }
}
