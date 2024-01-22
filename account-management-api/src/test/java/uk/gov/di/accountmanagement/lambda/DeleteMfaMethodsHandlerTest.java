package uk.gov.di.accountmanagement.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import org.junit.jupiter.api.Test;
import uk.gov.di.accountmanagement.entity.DeleteMfaMethodRequest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;

public class DeleteMfaMethodsHandlerTest {

    @Test
    void shouldReturn200ForSuccessfulRequest() {
        var handler = new DeleteMfaMethodHandler();
        var context = mock(Context.class);
        var event = new APIGatewayProxyRequestEvent();

        var result = handler.handleRequest(event, context);
        assertEquals(200, result.getStatusCode());
    }
}
