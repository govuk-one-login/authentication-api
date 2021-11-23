package uk.gov.di.authentication.shared.services;

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
import net.minidev.json.JSONArray;
import org.hamcrest.MatcherAssert;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.ClientSession;
import uk.gov.di.authentication.shared.entity.CustomScopeValue;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.entity.VectorOfTrust;
import uk.gov.di.authentication.shared.exceptions.ClientNotFoundException;
import uk.gov.di.authentication.shared.helpers.CookieHelper;
import uk.gov.di.authentication.shared.state.UserContext;

import java.net.URI;
import java.net.URISyntaxException;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static java.lang.String.format;
import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AuthorizationServiceTest {

    private static final URI REDIRECT_URI = URI.create("http://localhost/redirect");
    private AuthorizationService authorizationService;
    private final DynamoClientService dynamoClientService = mock(DynamoClientService.class);
    private final DynamoService dynamoService = mock(DynamoService.class);

    @BeforeEach
    void setUp() {
        authorizationService = new AuthorizationService(dynamoClientService, dynamoService);
    }

    @Test
    void shouldThrowClientNotFoundExceptionWhenClientDoesNotExist() {
        ClientID clientID = new ClientID();
        when(dynamoClientService.getClient(clientID.toString())).thenReturn(Optional.empty());

        ClientNotFoundException exception =
                Assertions.assertThrows(
                        ClientNotFoundException.class,
                        () -> authorizationService.isClientRedirectUriValid(clientID, REDIRECT_URI),
                        "Expected to throw exception");

        MatcherAssert.assertThat(
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
    void shouldGenerateSuccessfulAuthResponse() throws URISyntaxException {
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
                authorizationService.generateSuccessfulAuthResponse(authRequest, authCode, null);
        assertThat(authSuccessResponse.getState(), equalTo(state));
        assertThat(authSuccessResponse.getAuthorizationCode(), equalTo(authCode));
        assertThat(authSuccessResponse.getRedirectionURI(), equalTo(REDIRECT_URI));
    }

    @Test
    void shouldSuccessfullyValidateAuthRequest() {
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
    void shouldSuccessfullyValidateAccountManagementAuthRequest() {
        ClientID clientID = new ClientID();
        ResponseType responseType = new ResponseType(ResponseType.Value.CODE);
        Scope scope = new Scope(OIDCScopeValue.OPENID, CustomScopeValue.ACCOUNT_MANAGEMENT);
        when(dynamoClientService.getClient(clientID.toString()))
                .thenReturn(
                        Optional.of(
                                generateClientRegistry(
                                        REDIRECT_URI.toString(),
                                        clientID.toString(),
                                        List.of("openid", "am"))));
        Optional<ErrorObject> errorObject =
                authorizationService.validateAuthRequest(
                        generateAuthRequest(
                                clientID, REDIRECT_URI.toString(), responseType, scope));

        assertThat(errorObject, equalTo(Optional.empty()));
    }

    @Test
    void shouldReturnErrorForAccountManagementAuthRequestWhenScopeNotInClient() {
        ClientID clientID = new ClientID();
        ResponseType responseType = new ResponseType(ResponseType.Value.CODE);
        Scope scope = new Scope(OIDCScopeValue.OPENID, CustomScopeValue.ACCOUNT_MANAGEMENT);
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
    void shouldReturnErrorWhenInvalidVtrIsIncludedInAuthRequest() {
        ClientID clientID = new ClientID();
        ResponseType responseType = new ResponseType(ResponseType.Value.CODE);
        Scope scope = new Scope();
        scope.add(OIDCScopeValue.OPENID);
        when(dynamoClientService.getClient(clientID.toString()))
                .thenReturn(
                        Optional.of(
                                generateClientRegistry(
                                        REDIRECT_URI.toString(), clientID.toString())));
        JSONArray jsonArray = new JSONArray();
        jsonArray.add("Cm");
        AuthenticationRequest authRequest =
                new AuthenticationRequest.Builder(
                                responseType, scope, new ClientID(clientID), REDIRECT_URI)
                        .state(new State())
                        .nonce(new Nonce())
                        .customParameter("vtr", jsonArray.toJSONString())
                        .build();
        Optional<ErrorObject> errorObject = authorizationService.validateAuthRequest(authRequest);

        assertThat(
                errorObject,
                equalTo(
                        Optional.of(
                                new ErrorObject(
                                        OAuth2Error.INVALID_REQUEST_CODE,
                                        "Request vtr not valid"))));
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

    @Test
    void shouldCreateUserContextFromSessionAndClientSession() {
        String email = "joe.bloggs@example.com";
        Session session = new Session("a-session-id");
        session.setEmailAddress(email);
        ClientID clientId = new ClientID("client-id");
        when(dynamoClientService.getClient(clientId.getValue()))
                .thenReturn(
                        Optional.of(
                                generateClientRegistry(
                                        REDIRECT_URI.toString(), clientId.getValue())));
        when(dynamoService.getUserProfileByEmail(email)).thenReturn(mock(UserProfile.class));
        Scope scopes =
                new Scope(
                        OIDCScopeValue.OPENID, OIDCScopeValue.EMAIL, OIDCScopeValue.OFFLINE_ACCESS);
        AuthenticationRequest authRequest =
                new AuthenticationRequest.Builder(
                                new ResponseType(ResponseType.Value.CODE),
                                scopes,
                                clientId,
                                REDIRECT_URI)
                        .state(new State())
                        .nonce(new Nonce())
                        .build();
        ClientSession clientSession =
                new ClientSession(
                        authRequest.toParameters(), LocalDateTime.now(), mock(VectorOfTrust.class));
        UserContext userContext = authorizationService.buildUserContext(session, clientSession);

        assertEquals(userContext.getSession(), session);
        assertEquals(userContext.getClientSession(), clientSession);
    }

    @Test
    void shouldGetPersistentCookieIdFromExistingCookie() {
        Map<String, String> requestCookieHeader =
                Map.of(
                        CookieHelper.REQUEST_COOKIE_HEADER,
                        "di-persistent-session-id=some-persistent-id;gs=session-id.456");

        String persistentSessionId =
                authorizationService.getExistingOrCreateNewPersistentSessionId(requestCookieHeader);

        assertEquals(persistentSessionId, "some-persistent-id");
    }

    private ClientRegistry generateClientRegistry(String redirectURI, String clientID) {
        return generateClientRegistry(redirectURI, clientID, singletonList("openid"));
    }

    private ClientRegistry generateClientRegistry(
            String redirectURI, String clientID, List<String> scopes) {
        return new ClientRegistry()
                .setRedirectUrls(singletonList(redirectURI))
                .setClientID(clientID)
                .setContacts(singletonList("joe.bloggs@digital.cabinet-office.gov.uk"))
                .setPublicKey(null)
                .setScopes(scopes);
    }

    private AuthenticationRequest generateAuthRequest(
            ClientID clientID, String redirectUri, ResponseType responseType, Scope scope) {
        JSONArray jsonArray = new JSONArray();
        jsonArray.add("Cm.Cl");
        jsonArray.add("Cl");
        State state = new State();
        return new AuthenticationRequest.Builder(
                        responseType, scope, new ClientID(clientID), URI.create(redirectUri))
                .state(state)
                .nonce(new Nonce())
                .customParameter("vtr", jsonArray.toJSONString())
                .build();
    }
}
