package uk.gov.di.authentication.app.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.mock;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class DocAppCallbackHandlerTest {

    private final Context context = mock(Context.class);
    private DocAppCallbackHandler handler;

    @BeforeEach
    void setUp() {
        handler = new DocAppCallbackHandler();
    }

    @Test
    void shouldReturn200() {
        var event = new APIGatewayProxyRequestEvent();
        var response = handler.handleRequest(event, context);

        assertThat(response, hasStatus(200));
    }
}
