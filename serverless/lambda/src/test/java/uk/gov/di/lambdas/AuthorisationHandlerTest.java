package uk.gov.di.lambdas;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.LambdaLogger;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.entity.Session;
import uk.gov.di.helpers.RequestBodyHelper;
import uk.gov.di.services.ClientService;
import uk.gov.di.services.ConfigurationService;
import uk.gov.di.services.SessionService;

import java.net.URI;
import java.util.Map;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasEntry;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.matchers.APIGatewayProxyResponseEventMatcher.hasBody;
import static uk.gov.di.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class AuthorisationHandlerTest {

    private final Context context = mock(Context.class);
    private final ClientService clientService = mock(ClientService.class);
    private final ConfigurationService configService = mock(ConfigurationService.class);
    private final SessionService sessionService = mock(SessionService.class);

    private AuthorisationHandler handler;

    @BeforeEach
    public void setUp() {
        handler = new AuthorisationHandler(clientService, configService, sessionService);
        when(context.getLogger()).thenReturn(mock(LambdaLogger.class));
    }

    @Test
    void shouldRedirectToLoginOnSuccess() {
        AuthorizationCode authCode = new AuthorizationCode();
        AuthenticationSuccessResponse authSuccessResponse =
                new AuthenticationSuccessResponse(
                        URI.create("http://localhost:8080"),
                        authCode,
                        null,
                        null,
                        new State("some-state"),
                        null,
                        null);

        final URI loginUrl = URI.create("http://example.com");
        final Session session = new Session("a-session-id");

        when(clientService.getErrorForAuthorizationRequest(any(AuthorizationRequest.class)))
                .thenReturn(Optional.empty());
        when(clientService.getSuccessfulResponse(
                        any(AuthenticationRequest.class),
                        eq("joe.bloggs@digital.cabinet-office.gov.uk")))
                .thenReturn(authSuccessResponse);
        when(configService.getLoginURI()).thenReturn(loginUrl);
        when(sessionService.createSession()).thenReturn(session);

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setQueryStringParameters(
                Map.of(
                        "client_id", "test-id",
                        "redirect_uri", "http://localhost:8080",
                        "scope", "email,openid,profile",
                        "response_type", "code",
                        "state", "some-state"));
        APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);
        URI uri = URI.create(response.getHeaders().get("Location"));
        Map<String, String> requestParams = RequestBodyHelper.PARSE_REQUEST_BODY(uri.getQuery());

        assertThat(response, hasStatus(302));
        assertEquals(loginUrl.getAuthority(), uri.getAuthority());

        assertThat(requestParams, hasEntry("id", session.getSessionId()));

        verify(sessionService).save(eq(session));
    }

    @Test
    void shouldReturn400WhenAuthorisationRequestCannotBeParsed() {
        when(clientService.getErrorForAuthorizationRequest(any(AuthorizationRequest.class)))
                .thenReturn(Optional.empty());
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setQueryStringParameters(
                Map.of(
                        "client_id", "test-id",
                        "redirect_uri", "http://localhost:8080",
                        "scope", "email,openid,profile",
                        "invalid_parameter", "nonsense"));

        APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);

        assertThat(response, hasStatus(400));
        assertThat(response, hasBody("Cannot parse authentication request"));
    }

    @Test
    void shouldReturn400WhenAuthorisationRequestContainsInvalidData() {
        when(clientService.getErrorForAuthorizationRequest(any(AuthorizationRequest.class)))
                .thenReturn(Optional.of(OAuth2Error.INVALID_SCOPE));
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setQueryStringParameters(
                Map.of(
                        "client_id", "test-id",
                        "redirect_uri", "http://localhost:8080",
                        "scope", "email,openid,profile,non-existent-scope",
                        "response_type", "code"));

        APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);

        assertThat(response, hasStatus(302));
        assertEquals(
                "http://localhost:8080?error=invalid_scope&error_description=Invalid%2C+unknown+or+malformed+scope",
                response.getHeaders().get("Location"));
    }
}
