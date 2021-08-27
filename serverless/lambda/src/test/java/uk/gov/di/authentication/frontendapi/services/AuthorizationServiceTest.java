package uk.gov.di.authentication.frontendapi.services;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.entity.ClientRegistry;
import uk.gov.di.exceptions.ClientNotFoundException;

import java.net.URI;
import java.util.Optional;

import static java.lang.String.format;
import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AuthorizationServiceTest {

    private static final URI REDIRECT_URI = URI.create("http://localhost/redirect");
    private AuthorizationService authorizationService;
    private final DynamoClientService dynamoClientService = mock(DynamoClientService.class);

    @BeforeEach
    void setUp() {
        authorizationService = new AuthorizationService(dynamoClientService);
    }

    @Test
    void shouldThrowClientNotFoundExceptionWhenClientDoesNotExist() {
        ClientID clientID = new ClientID();
        when(dynamoClientService.getClient(clientID.toString())).thenReturn(Optional.empty());

        ClientNotFoundException exception =
                assertThrows(
                        ClientNotFoundException.class,
                        () -> authorizationService.isClientRedirectUriValid(clientID, REDIRECT_URI),
                        "Expected to throw exception");

        assertThat(
                exception.getMessage(),
                equalTo(format("No Client found for ClientID: %s", clientID)));
    }

    @Test
    void shouldReturnFalseIfClientUriIsInvalid() throws ClientNotFoundException {
        ClientID clientID = new ClientID();
        ClientRegistry clientRegistry =
                generateClientRegistry("http://localhost//", clientID.toString());
        when(dynamoClientService.getClient(clientID.toString()))
                .thenReturn(Optional.of(clientRegistry));
        assertFalse(authorizationService.isClientRedirectUriValid(clientID, REDIRECT_URI));
    }

    @Test
    void shouldReturnTrueIfRedirectUriIsValid() throws ClientNotFoundException {
        ClientID clientID = new ClientID();
        ClientRegistry clientRegistry =
                generateClientRegistry(REDIRECT_URI.toString(), clientID.toString());
        when(dynamoClientService.getClient(clientID.toString()))
                .thenReturn(Optional.of(clientRegistry));
        assertTrue(authorizationService.isClientRedirectUriValid(clientID, REDIRECT_URI));
    }

    @Test
    void shouldGenerateSuccessfulAuthResponse() {
        ClientID clientID = new ClientID();
        AuthorizationCode authCode = new AuthorizationCode();
        State state = new State();
        Scope scope = new Scope();
        scope.add(OIDCScopeValue.OPENID);
        ResponseType responseType = new ResponseType(ResponseType.Value.CODE);
        AuthenticationRequest authRequest =
                new AuthenticationRequest.Builder(responseType, scope, clientID, REDIRECT_URI)
                        .state(state)
                        .nonce(new Nonce())
                        .build();

        AuthenticationSuccessResponse authSuccessResponse =
                authorizationService.generateSuccessfulAuthResponse(authRequest, authCode);
        assertThat(authSuccessResponse.getState(), equalTo(state));
        assertThat(authSuccessResponse.getAuthorizationCode(), equalTo(authCode));
        assertThat(authSuccessResponse.getRedirectionURI(), equalTo(REDIRECT_URI));
    }

    @Test
    void shouldSuccessfullyValidAuthRequest() {
        ClientID clientID = new ClientID();
        ResponseType responseType = new ResponseType(ResponseType.Value.CODE);
        Scope scope = new Scope();
        scope.add(OIDCScopeValue.OPENID);
        when(dynamoClientService.getClient(clientID.toString()))
                .thenReturn(
                        Optional.of(
                                generateClientRegistry(
                                        REDIRECT_URI.toString(), clientID.toString())));
        Optional<ErrorObject> errorObject =
                authorizationService.validateAuthRequest(
                        generateAuthRequest(
                                clientID, REDIRECT_URI.toString(), responseType, scope));

        assertThat(errorObject, equalTo(Optional.empty()));
    }

    @Test
    void shouldReturnErrorWhenClientIdIsNotValidInAuthRequest() {
        ClientID clientID = new ClientID();
        ResponseType responseType = new ResponseType(ResponseType.Value.CODE);
        Scope scope = new Scope();
        scope.add(OIDCScopeValue.OPENID);
        when(dynamoClientService.getClient(clientID.toString())).thenReturn(Optional.empty());
        Optional<ErrorObject> errorObject =
                authorizationService.validateAuthRequest(
                        generateAuthRequest(
                                clientID, REDIRECT_URI.toString(), responseType, scope));

        assertThat(errorObject, equalTo(Optional.of(OAuth2Error.UNAUTHORIZED_CLIENT)));
    }

    @Test
    void shouldReturnErrorWhenResponseCodeIsNotValidInAuthRequest() {
        ClientID clientID = new ClientID();
        ResponseType responseType =
                new ResponseType(ResponseType.Value.TOKEN, ResponseType.Value.CODE);
        Scope scope = new Scope();
        scope.add(OIDCScopeValue.OPENID);
        when(dynamoClientService.getClient(clientID.toString()))
                .thenReturn(
                        Optional.of(
                                generateClientRegistry(
                                        REDIRECT_URI.toString(), clientID.toString())));
        Optional<ErrorObject> errorObject =
                authorizationService.validateAuthRequest(
                        generateAuthRequest(
                                clientID, REDIRECT_URI.toString(), responseType, scope));

        assertThat(errorObject, equalTo(Optional.of(OAuth2Error.UNSUPPORTED_RESPONSE_TYPE)));
    }

    @Test
    void shouldReturnErrorWhenScopeIsNotValidInAuthRequest() {
        ClientID clientID = new ClientID();
        ResponseType responseType = new ResponseType(ResponseType.Value.CODE);
        Scope scope = new Scope();
        scope.add(OIDCScopeValue.OPENID);
        scope.add(OIDCScopeValue.EMAIL);
        when(dynamoClientService.getClient(clientID.toString()))
                .thenReturn(
                        Optional.of(
                                generateClientRegistry(
                                        REDIRECT_URI.toString(), clientID.toString())));
        Optional<ErrorObject> errorObject =
                authorizationService.validateAuthRequest(
                        generateAuthRequest(
                                clientID, REDIRECT_URI.toString(), responseType, scope));

        assertThat(errorObject, equalTo(Optional.of(OAuth2Error.INVALID_SCOPE)));
    }

    @Test
    void shouldReturnErrorWhenStateIsNotIncludedInAuthRequest() {
        ClientID clientID = new ClientID();
        ResponseType responseType = new ResponseType(ResponseType.Value.CODE);
        Scope scope = new Scope();
        scope.add(OIDCScopeValue.OPENID);
        when(dynamoClientService.getClient(clientID.toString()))
                .thenReturn(
                        Optional.of(
                                generateClientRegistry(
                                        REDIRECT_URI.toString(), clientID.toString())));
        AuthenticationRequest authRequest =
                new AuthenticationRequest.Builder(
                                responseType, scope, new ClientID(clientID), REDIRECT_URI)
                        .nonce(new Nonce())
                        .build();
        Optional<ErrorObject> errorObject = authorizationService.validateAuthRequest(authRequest);

        assertThat(
                errorObject,
                equalTo(
                        Optional.of(
                                new ErrorObject(
                                        OAuth2Error.INVALID_REQUEST_CODE,
                                        "Request is missing state parameter"))));
    }

    @Test
    void shouldReturnErrorWhenNonceIsNotIncludedInAuthRequest() {
        ClientID clientID = new ClientID();
        ResponseType responseType = new ResponseType(ResponseType.Value.CODE);
        Scope scope = new Scope();
        scope.add(OIDCScopeValue.OPENID);
        when(dynamoClientService.getClient(clientID.toString()))
                .thenReturn(
                        Optional.of(
                                generateClientRegistry(
                                        REDIRECT_URI.toString(), clientID.toString())));
        AuthenticationRequest authRequest =
                new AuthenticationRequest.Builder(
                                responseType, scope, new ClientID(clientID), REDIRECT_URI)
                        .state(new State())
                        .build();
        Optional<ErrorObject> errorObject = authorizationService.validateAuthRequest(authRequest);

        assertThat(
                errorObject,
                equalTo(
                        Optional.of(
                                new ErrorObject(
                                        OAuth2Error.INVALID_REQUEST_CODE,
                                        "Request is missing nonce parameter"))));
    }

    @Test
    void shouldThrowExceptionWhenRedirectUriIsInvalidInAuthRequest() {
        ClientID clientID = new ClientID();
        ResponseType responseType = new ResponseType(ResponseType.Value.CODE);
        String redirectURi = "http://localhost/redirect";
        Scope scope = new Scope();
        scope.add(OIDCScopeValue.OPENID);
        when(dynamoClientService.getClient(clientID.toString()))
                .thenReturn(
                        Optional.of(
                                generateClientRegistry(
                                        "http://localhost/wrong-redirect", clientID.toString())));

        RuntimeException exception =
                assertThrows(
                        RuntimeException.class,
                        () ->
                                authorizationService.validateAuthRequest(
                                        generateAuthRequest(
                                                clientID, redirectURi, responseType, scope)),
                        "Expected to throw exception");
        assertThat(
                exception.getMessage(),
                equalTo(format("Invalid Redirect in request %s", redirectURi)));
    }

    private ClientRegistry generateClientRegistry(String redirectURI, String clientID) {
        return new ClientRegistry()
                .setRedirectUrls(singletonList(redirectURI))
                .setClientID(clientID)
                .setContacts(singletonList("joe.bloggs@digital.cabinet-office.gov.uk"))
                .setPublicKey(null)
                .setScopes(singletonList("openid"));
    }

    private AuthenticationRequest generateAuthRequest(
            ClientID clientID, String redirectUri, ResponseType responseType, Scope scope) {
        State state = new State();
        return new AuthenticationRequest.Builder(
                        responseType, scope, new ClientID(clientID), URI.create(redirectUri))
                .state(state)
                .nonce(new Nonce())
                .build();
    }
}
