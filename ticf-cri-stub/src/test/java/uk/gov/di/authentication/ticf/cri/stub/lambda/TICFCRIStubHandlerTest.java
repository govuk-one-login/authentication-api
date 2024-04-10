package uk.gov.di.authentication.ticf.cri.stub.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;

class TICFCRIStubHandlerTest {
    @Test
    void shouldReturn200ForSuccessfulRequest() {
        var handler = new TICFCRIStubHandler();
        var context = mock(Context.class);
        var event = new APIGatewayProxyRequestEvent();

        var result = handler.handleRequest(event, context);
        assertEquals(200, result.getStatusCode());
        assertEquals("Hello world", result.getBody());
    }
}
