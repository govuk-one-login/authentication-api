package uk.gov.di.services;

import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ResponseMode;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.OIDCError;
import org.junit.jupiter.api.Test;
import uk.gov.di.entity.Client;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static java.util.Collections.singletonList;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;

class ClientServiceTest {
    private static final AuthorizationCodeService AUTHORIZATION_CODE_SERVICE =
            mock(AuthorizationCodeService.class);

    private static final ClientService CLIENT_SERVICE =
            new ClientService(
                    new ArrayList<>(List.of(
                            new Client(
                                    "client-name",
                                    "test-id",
                                    "test-secret",
                                    List.of("email"),
                                    List.of("code"),
                                    List.of("http://localhost:8080"),
                                    List.of("contact@example.com")))),
                    AUTHORIZATION_CODE_SERVICE);

    @Test
    void validatesRegisteredClientSuccessfully() {
        Optional<ErrorObject> error =
                CLIENT_SERVICE.getErrorForAuthorizationRequest(
                        new AuthorizationRequest(
                                URI.create("http://localhost:8080"),
                                new ResponseType("code"),
                                ResponseMode.FORM_POST,
                                new ClientID("test-id"),
                                URI.create("http://localhost:8080"),
                                new Scope("email"),
                                new State()));

        assertTrue(error.isEmpty());
    }

    @Test
    void authorizationRequestInvalidIfClientNotRegistered() {
        Optional<ErrorObject> error =
                CLIENT_SERVICE.getErrorForAuthorizationRequest(
                        new AuthorizationRequest(
                                URI.create("test"),
                                new ResponseType(),
                                ResponseMode.FORM_POST,
                                new ClientID("not-a-client"),
                                URI.create("http://localhost:8080"),
                                new Scope("openid"),
                                new State()));

        assertEquals(OIDCError.UNMET_AUTHENTICATION_REQUIREMENTS, error.get());
    }

    @Test
    void authorizationRequestInvalidIfClientRequestsForbiddenScope() {
        Optional<ErrorObject> error =
                CLIENT_SERVICE.getErrorForAuthorizationRequest(
                        new AuthorizationRequest(
                                URI.create("http://localhost:8080"),
                                new ResponseType("code"),
                                ResponseMode.FORM_POST,
                                new ClientID("test-id"),
                                URI.create("http://localhost:8080"),
                                new Scope("phone"),
                                new State()));

        assertEquals(OAuth2Error.INVALID_SCOPE, error.get());
    }

    @Test
    void authorizationRequestInvalidIfClientRequestsForbiddenResponseType() {
        Optional<ErrorObject> error =
                CLIENT_SERVICE.getErrorForAuthorizationRequest(
                        new AuthorizationRequest(
                                URI.create("http://localhost:8080"),
                                new ResponseType("token"),
                                ResponseMode.FORM_POST,
                                new ClientID("test-id"),
                                URI.create("http://localhost:8080"),
                                new Scope("email"),
                                new State()));

        assertEquals(OAuth2Error.UNSUPPORTED_RESPONSE_TYPE, error.get());
    }

    @Test
    void authorizationRequestInvalidIfClientRequestContainsInvalidRedirectUri() {
        Optional<ErrorObject> error =
                CLIENT_SERVICE.getErrorForAuthorizationRequest(
                        new AuthorizationRequest(
                                URI.create("http://localhost:8080"),
                                new ResponseType("code"),
                                ResponseMode.FORM_POST,
                                new ClientID("test-id"),
                                URI.create("http://localhost:8080/wrong"),
                                new Scope("email"),
                                new State()));

        assertEquals(OAuth2Error.INVALID_REQUEST_URI, error.get());
    }

    @Test
    void shouldBeAbleToAddNewClient() {
        Client client = CLIENT_SERVICE.addClient(
                "test-client",
                singletonList("http://some-service/redirect"),
                singletonList("test-client@test.com")
        );

        assertEquals(client, CLIENT_SERVICE.getClient(client.clientId()).get());
    }
}
