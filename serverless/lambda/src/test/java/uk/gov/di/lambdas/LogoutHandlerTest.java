package uk.gov.di.lambdas;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.entity.Session;
import uk.gov.di.helpers.IDTokenGenerator;
import uk.gov.di.services.ConfigurationService;
import uk.gov.di.services.SessionService;

import java.net.URI;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class LogoutHandlerTest {

    private final Context context = mock(Context.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final SessionService sessionService = mock(SessionService.class);
    private static final String SET_COOKIE = "Set-Cookie";
    private static final String SESSION_ID = "a-session-id";
    private static final String CLIENT_SESSION_ID = "client-session-id";
    private static final URI DEFAULT_LOGOUT_URI = URI.create("http://localhost/logout");
    private LogoutHandler handler;

    @BeforeEach
    public void setUp() {
        handler = new LogoutHandler(configurationService);
        when(configurationService.getDefaultLogoutURI()).thenReturn(DEFAULT_LOGOUT_URI);
    }

    @Test
    public void shouldRedirectToDefaultLogoutUriForSuccessfulRequest() throws JOSEException {
        RSAKey signingKey =
                new RSAKeyGenerator(2048).keyID(UUID.randomUUID().toString()).generate();
        SignedJWT signedJWT =
                IDTokenGenerator.generateIDToken(
                        "client-id", new Subject(), "http://localhost-rp", signingKey);
        State state = new State();
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        generateValidSession();
        event.setHeaders(Map.of(SET_COOKIE, buildCookieString()));
        event.setQueryStringParameters(
                Map.of(
                        "id_token_hint", signedJWT.serialize(),
                        "post_logout_redirect_uri", "http://localhost:8000/logout",
                        "state", state.toString()));
        APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);

        assertThat(response, hasStatus(302));
        assertThat(response.getHeaders().get("Location"), equalTo(DEFAULT_LOGOUT_URI.toString()));
    }

    private void generateValidSession() {
        when(sessionService.getSessionFromRequestHeaders(anyMap()))
                .thenReturn(Optional.of(new Session(SESSION_ID, CLIENT_SESSION_ID)));
    }

    private String buildCookieString() {
        return format(
                "%s=%s.%s; Max-Age=%d; %s",
                "gs", SESSION_ID, CLIENT_SESSION_ID, 1800, "Secure; HttpOnly;");
    }
}
