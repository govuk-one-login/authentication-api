package uk.gov.di.lambdas;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.services.ConfigurationService;
import uk.gov.di.services.SessionService;

import java.util.Map;

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.mock;
import static uk.gov.di.Messages.ERROR_MISSING_REQUEST_PARAMETERS;
import static uk.gov.di.entity.NotificationType.VERIFY_EMAIL;
import static uk.gov.di.matchers.APIGatewayProxyResponseEventMatcher.hasBody;
import static uk.gov.di.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class VerifyCodeRequestHandlerTest {

    private final Context context = mock(Context.class);
    private final SessionService sessionService = mock(SessionService.class);
    private final ConfigurationService configService = mock(ConfigurationService.class);
    private VerifyCodeHandler handler;

    @BeforeEach
    public void setup() {
        handler = new VerifyCodeHandler(sessionService, configService);
    }

    @Test
    public void shouldReturn200ForValidRequest() {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("Session-Id", "a-session-id"));
        event.setBody(
                format(
                        "{ \"code\": \"123456\", \"notificationType\": \"%s\" }",
                        VERIFY_EMAIL));

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);
        assertThat(result, hasStatus(200));
        assertThat(result, hasBody("OK"));
    }

    @Test
    public void shouldReturn400IfRequestIsMissingNotificationType() {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("Session-Id", "a-session-id"));
        event.setBody(
                format(
                        "{ \"code\": \"123456\"}",
                        VERIFY_EMAIL));

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);
        assertThat(result, hasStatus(400));
        assertThat(result, hasBody(ERROR_MISSING_REQUEST_PARAMETERS));
    }
}