package uk.gov.di.lambdas;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.services.ClientService;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
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
    void shouldRedirectToSuppliedUrlOnSuccess() {
        when(CLIENT_SERVICE.getErrorForAuthorizationRequest(any(AuthorizationRequest.class))).thenReturn(Optional.empty());
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setMultiValueQueryStringParameters(
                Map.of(
                        "client_id", List.of("test-id"),
                        "redirect_uri", List.of("http://localhost:8080"),
                        "scope", List.of("email,openid,profile"),
                        "response_type", List.of("code")
                )
        );

        APIGatewayProxyResponseEvent response = handler.handleRequest(event, CONTEXT);

        assertEquals(302, response.getStatusCode());
        assertEquals("http://localhost:8080", response.getHeaders().get("Location"));
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
        event.setMultiValueQueryStringParameters(
                Map.of(
                        "client_id", List.of("test-id"),
                        "redirect_uri", List.of("http://localhost:8080"),
                        "scope", List.of("email,openid,profile,non-existent-scope"),
                        "response_type", List.of("code")
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