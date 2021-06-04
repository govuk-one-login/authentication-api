package uk.gov.di.lambdas;

import com.amazonaws.services.lambda.runtime.Context;
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
import uk.gov.di.helpers.RequestBodyHelper;
import uk.gov.di.services.ClientService;

import java.net.MalformedURLException;
import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AuthorisationHandlerTest {

    private final Context CONTEXT = mock(Context.class);

    private final ClientService CLIENT_SERVICE = mock(ClientService.class);
    private AuthorisationHandler handler;

    @BeforeEach
    public void setUp() {
        handler = new AuthorisationHandler(CLIENT_SERVICE);
    }

    @Test
    void shouldRedirectToSuppliedUrlOnSuccess() throws MalformedURLException {
        AuthorizationCode authCode = new AuthorizationCode();
        AuthenticationSuccessResponse authSuccessResponse = new AuthenticationSuccessResponse(
                URI.create("http://localhost:8080"),
                authCode,
                null,
                null,
                new State("some-state"),
                null,
                null);

        when(CLIENT_SERVICE.getErrorForAuthorizationRequest(any(AuthorizationRequest.class))).thenReturn(Optional.empty());
        when(CLIENT_SERVICE.getSuccessfulResponse(any(AuthenticationRequest.class), eq("joe.bloggs@digital.cabinet-office.gov.uk")))
                .thenReturn(authSuccessResponse);

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setMultiValueQueryStringParameters(
                Map.of(
                        "client_id", List.of("test-id"),
                        "redirect_uri", List.of("http://localhost:8080"),
                        "scope", List.of("email,openid,profile"),
                        "response_type", List.of("code"),
                        "state", List.of("some-state")
                )
        );
        APIGatewayProxyResponseEvent response = handler.handleRequest(event, CONTEXT);
        URI uri = URI.create(response.getHeaders().get("Location"));
        Map<String, String> requestParams = RequestBodyHelper.PARSE_REQUEST_BODY(uri.getQuery());

        assertEquals(302, response.getStatusCode());
        assertEquals("localhost:8080", uri.toURL().getAuthority());
        assertEquals(authCode.toString(), requestParams.get("code"));
        assertEquals("some-state", requestParams.get("state"));
    }

    @Test
    void shouldReturn400WhenAuthorisationRequestCannotBeParsed() {
        when(CLIENT_SERVICE.getErrorForAuthorizationRequest(any(AuthorizationRequest.class))).thenReturn(Optional.empty());
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setMultiValueQueryStringParameters(
                Map.of(
                        "client_id", List.of("test-id"),
                        "redirect_uri", List.of("http://localhost:8080"),
                        "scope", List.of("email,openid,profile"),
                        "invalid_parameter", List.of("nonsense")
                )
        );

        APIGatewayProxyResponseEvent response = handler.handleRequest(event, CONTEXT);

        assertEquals(400, response.getStatusCode());
        assertEquals("Cannot parse authentication request", response.getBody());
    }

    @Test
    void shouldReturn400WhenAuthorisationRequestContainsInvalidData() {
        when(CLIENT_SERVICE.getErrorForAuthorizationRequest(any(AuthorizationRequest.class)))
                .thenReturn(Optional.of(OAuth2Error.INVALID_SCOPE));
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setQueryStringParameters(
                Map.of(
                        "client_id", "test-id",
                        "redirect_uri", "http://localhost:8080",
                        "scope", "email,openid,profile,non-existent-scope",
                        "response_type", "code"
                )
        );

        APIGatewayProxyResponseEvent response = handler.handleRequest(event, CONTEXT);

        assertEquals(302, response.getStatusCode());
        assertEquals(
                "http://localhost:8080?error=invalid_scope&error_description=Invalid%2C+unknown+or+malformed+scope",
                response.getHeaders().get("Location")
        );
    }
}