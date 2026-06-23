package uk.gov.di.orchestration.sis.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;

public class SISJwksHandlerTest {
    @Test
    void shouldCheckLambdaReturnsExpectedValue() {
        var sisJwksHandler = new SISJwksHandler();

        var response =
                sisJwksHandler.handleRequest(
                        new APIGatewayProxyRequestEvent(), mock(Context.class));

        assertEquals(200, response.getStatusCode());
        assertEquals("Test lambda", response.getBody());
    }
}
