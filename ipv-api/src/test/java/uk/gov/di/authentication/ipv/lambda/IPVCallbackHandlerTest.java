package uk.gov.di.authentication.ipv.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.net.URI;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class IPVCallbackHandlerTest {

    private final Context context = mock(Context.class);
    private final ConfigurationService configService = mock(ConfigurationService.class);
    private static final URI LOGIN_URL = URI.create("https://example.com");
    private IPVCallbackHandler handler;

    @BeforeEach
    void setUp() {
        handler = new IPVCallbackHandler(configService);
        when(configService.getLoginURI()).thenReturn(LOGIN_URL);
    }

    @Test
    void shouldRedirectToLoginUri() {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        APIGatewayProxyResponseEvent response = makeHandlerRequest(event);
        assertThat(response, hasStatus(302));
        assertThat(response.getHeaders().get("Location"), equalTo(LOGIN_URL.toString()));
    }

    private APIGatewayProxyResponseEvent makeHandlerRequest(APIGatewayProxyRequestEvent event) {
        return handler.handleRequest(event, context);
    }
}
