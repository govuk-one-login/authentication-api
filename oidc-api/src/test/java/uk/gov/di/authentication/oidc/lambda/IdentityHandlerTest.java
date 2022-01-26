package uk.gov.di.authentication.oidc.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.mock;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class IdentityHandlerTest {

    private ConfigurationService configurationService = mock(ConfigurationService.class);
    private final Context context = mock(Context.class);
    private IdentityHandler handler;

    @BeforeEach
    void setUp() {
        handler = new IdentityHandler(configurationService);
    }

    @Test
    void shouldReturn204ForSuccessfulRequest() {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(204));
    }
}
