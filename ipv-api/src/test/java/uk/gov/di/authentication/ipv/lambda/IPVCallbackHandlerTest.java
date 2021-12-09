package uk.gov.di.authentication.ipv.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.Tokens;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.ipv.services.AuthorisationResponseService;
import uk.gov.di.authentication.ipv.services.IPVTokenService;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class IPVCallbackHandlerTest {

    private final Context context = mock(Context.class);
    private final ConfigurationService configService = mock(ConfigurationService.class);
    private final AuthorisationResponseService responseService =
            mock(AuthorisationResponseService.class);
    private final IPVTokenService ipvTokenService = mock(IPVTokenService.class);
    private static final URI LOGIN_URL = URI.create("https://example.com");
    private static final AuthorizationCode AUTH_CODE = new AuthorizationCode();
    private static final String COOKIE = "Cookie";
    private static final String SESSION_ID = "a-session-id";
    private static final String CLIENT_SESSION_ID = "a-client-session-id";
    private static final State STATE = new State();
    private IPVCallbackHandler handler;

    @BeforeEach
    void setUp() {
        handler = new IPVCallbackHandler(configService, responseService, ipvTokenService);
        when(configService.getLoginURI()).thenReturn(LOGIN_URL);
    }

    @Test
    void shouldRedirectToLoginUriForSuccessfulResponse() {
        TokenResponse successfulTokenResponse =
                new AccessTokenResponse(new Tokens(new BearerAccessToken(), null));
        TokenRequest tokenRequest = mock(TokenRequest.class);
        Map<String, String> responseHeaders = new HashMap<>();
        responseHeaders.put("code", AUTH_CODE.getValue());
        responseHeaders.put("state", STATE.getValue());
        when(responseService.validateResponse(responseHeaders, SESSION_ID))
                .thenReturn(Optional.empty());
        when(ipvTokenService.constructTokenRequest(AUTH_CODE.getValue())).thenReturn(tokenRequest);
        when(ipvTokenService.sendTokenRequest(tokenRequest)).thenReturn(successfulTokenResponse);

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setQueryStringParameters(responseHeaders);
        event.setHeaders(Map.of(COOKIE, buildCookieString()));
        APIGatewayProxyResponseEvent response = makeHandlerRequest(event);

        assertThat(response, hasStatus(302));
        assertThat(response.getHeaders().get("Location"), equalTo(LOGIN_URL.toString()));
    }

    @Test
    void shouldThrowWhenAuthnResponseContainsError() {
        ErrorObject errorObject =
                new ErrorObject(
                        "invalid_request_redirect_uri", "redirect_uri param must be provided");
        Map<String, String> responseHeaders = new HashMap<>();
        responseHeaders.put("code", AUTH_CODE.getValue());
        responseHeaders.put("state", STATE.getValue());
        responseHeaders.put("error", errorObject.toString());

        when(responseService.validateResponse(responseHeaders, SESSION_ID))
                .thenReturn(Optional.of(new ErrorObject(errorObject.getCode())));

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of(COOKIE, buildCookieString()));
        event.setQueryStringParameters(responseHeaders);

        assertThrows(
                RuntimeException.class,
                () -> handler.handleRequest(event, context),
                "Expected to throw exception");

        verifyNoInteractions(ipvTokenService);
    }

    private APIGatewayProxyResponseEvent makeHandlerRequest(APIGatewayProxyRequestEvent event) {
        return handler.handleRequest(event, context);
    }

    private static String buildCookieString() {
        return format(
                "%s=%s.%s; Max-Age=%d; %s",
                "gs", SESSION_ID, CLIENT_SESSION_ID, 3600, "Secure; HttpOnly;");
    }
}
