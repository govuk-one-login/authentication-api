package uk.gov.di.authentication.oidc.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.oidc.entity.IdentityErrorResponse;
import uk.gov.di.authentication.oidc.services.AccessTokenService;
import uk.gov.di.authentication.shared.exceptions.AccessTokenException;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.util.List;
import java.util.Map;

import static com.nimbusds.oauth2.sdk.token.BearerTokenError.INVALID_TOKEN;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class IdentityHandlerTest {

    private ConfigurationService configurationService = mock(ConfigurationService.class);
    private final AccessTokenService accessTokenService = mock(AccessTokenService.class);
    private static final Map<String, List<String>> INVALID_TOKEN_RESPONSE =
            new IdentityErrorResponse(INVALID_TOKEN).toHTTPResponse().getHeaderMap();
    private final Context context = mock(Context.class);
    private IdentityHandler handler;

    @BeforeEach
    void setUp() {
        handler = new IdentityHandler(configurationService, accessTokenService);
    }

    @Test
    void shouldReturn204ForSuccessfulRequest() {
        AccessToken accessToken = new BearerAccessToken();
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("Authorization", accessToken.toAuthorizationHeader()));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(204));
    }

    @Test
    void shouldReturn401WhenAccessTokenIsMissing() {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(401));
    }

    @Test
    void shouldReturn401WhenBearerTokenIsNotParseable() throws AccessTokenException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("Authorization", "this-is-not-a-valid-token"));
        AccessTokenException accessTokenException =
                new AccessTokenException("Unable to parse AccessToken", INVALID_TOKEN);
        when(accessTokenService.parse("this-is-not-a-valid-token")).thenThrow(accessTokenException);

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(401));
        assertEquals(INVALID_TOKEN_RESPONSE, result.getMultiValueHeaders());
    }
}
