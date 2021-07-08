package uk.gov.di.lambdas;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.entity.Session;
import uk.gov.di.services.ConfigurationService;
import uk.gov.di.services.SessionService;

import java.util.Map;
import java.util.Optional;

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

public class MfaHandlerTest {

    private MfaHandler handler;
    public static final String TEST_EMAIL_ADDRESS = "test@test.com";
    private final Context context = mock(Context.class);
    private final SessionService sessionService = mock(SessionService.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);

    @BeforeEach
    public void setUp() {
        handler = new MfaHandler(configurationService, sessionService);
    }

    @Test
    public void shouldReturn200ForSuccessfulRequest() {
        usingValidSession(TEST_EMAIL_ADDRESS);
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("Session-Id", "a-session-id"));
        event.setBody(format("{ \"email\": \"%s\"}", TEST_EMAIL_ADDRESS));

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(200));
    }

    @Test
    public void shouldReturn400WhenSessionIdIsInvalid() {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("Session-Id", "a-session-id"));
        event.setBody(format("{ \"email\": \"%s\"}", TEST_EMAIL_ADDRESS));

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
    }

    private void usingValidSession(String email) {
        when(sessionService.getSessionFromRequestHeaders(anyMap()))
                .thenReturn(Optional.of(new Session("a-session-id").setEmailAddress(email)));
    }
}
