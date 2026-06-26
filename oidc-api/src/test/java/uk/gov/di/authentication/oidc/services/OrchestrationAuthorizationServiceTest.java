package uk.gov.di.authentication.oidc.services;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCClaimsRequest;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import uk.gov.di.orchestration.shared.entity.ClientRegistry;
import uk.gov.di.orchestration.shared.exceptions.ClientNotFoundException;
import uk.gov.di.orchestration.shared.helpers.CookieHelper;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.CrossBrowserOrchestrationService;
import uk.gov.di.orchestration.shared.services.DynamoClientService;
import uk.gov.di.orchestration.shared.services.OrchJwtService;
import uk.gov.di.orchestration.shared.services.StateStorageService;
import uk.gov.di.orchestration.sharedtest.logging.CaptureLoggingExtension;

import java.net.URI;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static java.lang.String.format;
import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.orchestration.shared.helpers.PersistentIdHelper.isValidPersistentSessionCookieWithDoubleDashedTimestamp;
import static uk.gov.di.orchestration.sharedtest.helper.JsonArrayHelper.jsonArrayOf;
import static uk.gov.di.orchestration.sharedtest.logging.LogEventMatcher.withMessageContaining;
import static uk.gov.di.orchestration.sharedtest.utils.KeyPairUtils.generateRsaKeyPair;

class OrchestrationAuthorizationServiceTest {

    private static final URI REDIRECT_URI = URI.create("http://localhost/redirect");
    private static final ClientID CLIENT_ID = new ClientID();
    private static final State STATE = new State();
    private static final Nonce NONCE = new Nonce();
    private static final String SIGNING_KEY_ALIAS = "test-signing-key";
    private OrchestrationAuthorizationService orchestrationAuthorizationService;
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final DynamoClientService dynamoClientService = mock(DynamoClientService.class);
    private final CrossBrowserOrchestrationService crossBrowserOrchestrationService =
            mock(CrossBrowserOrchestrationService.class);
    private final StateStorageService stateStorageService = mock(StateStorageService.class);
    private final OrchJwtService orchJwtService = mock(OrchJwtService.class);
    private RSAPublicKey publicEncryptionKey;

    @RegisterExtension
    public final CaptureLoggingExtension logging =
            new CaptureLoggingExtension(OrchestrationAuthorizationService.class);

    @BeforeEach
    void setUp() throws Exception {
        orchestrationAuthorizationService =
                new OrchestrationAuthorizationService(
                        configurationService,
                        dynamoClientService,
                        crossBrowserOrchestrationService,
                        stateStorageService,
                        orchJwtService);
        var keyPair = generateRsaKeyPair();
        var publicCertificateAsPem =
                "-----BEGIN PUBLIC KEY-----\n"
                        + Base64.getMimeEncoder().encodeToString(keyPair.getPublic().getEncoded())
                        + "\n-----END PUBLIC KEY-----\n";
        when(configurationService.getOrchestrationToAuthenticationEncryptionPublicKey())
                .thenReturn(publicCertificateAsPem);
        publicEncryptionKey =
                new RSAKey.Builder((RSAKey) JWK.parseFromPEMEncodedObjects(publicCertificateAsPem))
                        .build()
                        .toRSAPublicKey();
        when(configurationService.getAuthSigningKeyAlias()).thenReturn(SIGNING_KEY_ALIAS);
    }

    @AfterEach
    void tearDown() {
        assertThat(logging.events(), not(hasItem(withMessageContaining(CLIENT_ID.toString()))));
    }

    @Test
    void shouldThrowClientNotFoundExceptionWhenClientDoesNotExist() {
        when(dynamoClientService.getClient(CLIENT_ID.toString())).thenReturn(Optional.empty());

        ClientNotFoundException exception =
                Assertions.assertThrows(
                        ClientNotFoundException.class,
                        () ->
                                orchestrationAuthorizationService.isClientRedirectUriValid(
                                        CLIENT_ID, REDIRECT_URI),
                        "Expected to throw exception");

        assertThat(
                exception.getMessage(),
                equalTo(format("No Client found for ClientID: %s", CLIENT_ID)));
    }

    @Test
    void shouldReturnFalseIfClientUriIsInvalid() throws ClientNotFoundException {
        when(dynamoClientService.getClient(CLIENT_ID.toString()))
                .thenReturn(
                        Optional.of(
                                generateClientRegistry(
                                        "http://localhost//", CLIENT_ID.toString())));
        assertFalse(
                orchestrationAuthorizationService.isClientRedirectUriValid(
                        CLIENT_ID, REDIRECT_URI));
    }

    @Test
    void shouldReturnTrueIfRedirectUriIsValid() throws ClientNotFoundException {
        when(dynamoClientService.getClient(CLIENT_ID.toString()))
                .thenReturn(
                        Optional.of(
                                generateClientRegistry(
                                        REDIRECT_URI.toString(), CLIENT_ID.toString())));
        assertTrue(
                orchestrationAuthorizationService.isClientRedirectUriValid(
                        CLIENT_ID, REDIRECT_URI));
    }

    @Test
    void shouldReturnTrueIfRedirectUriIsValidWhenClientIsPassedIn() {
        var client = generateClientRegistry(REDIRECT_URI.toString(), CLIENT_ID.toString());
        assertTrue(
                orchestrationAuthorizationService.isClientRedirectUriValid(client, REDIRECT_URI));
    }

    @Test
    void shouldReturnFalseIfRedirectUriIsInvalidWhenClientIsPassedIn() {
        var client = generateClientRegistry("http://localhost//", CLIENT_ID.toString());
        assertFalse(
                orchestrationAuthorizationService.isClientRedirectUriValid(client, REDIRECT_URI));
    }

    @Test
    void shouldGenerateSuccessfulAuthResponse() {
        AuthorizationCode authCode = new AuthorizationCode();
        Scope scope = new Scope();
        scope.add(OIDCScopeValue.OPENID);
        ResponseType responseType = new ResponseType(ResponseType.Value.CODE);
        AuthenticationRequest authRequest =
                generateAuthRequest(REDIRECT_URI.toString(), responseType, scope);

        AuthenticationSuccessResponse authSuccessResponse =
                orchestrationAuthorizationService.generateSuccessfulAuthResponse(
                        authRequest, authCode, REDIRECT_URI, STATE);
        assertThat(authSuccessResponse.getState(), equalTo(STATE));
        assertThat(authSuccessResponse.getAuthorizationCode(), equalTo(authCode));
        assertThat(authSuccessResponse.getRedirectionURI(), equalTo(REDIRECT_URI));
    }

    @Test
    void shouldGetPersistentCookieIdFromExistingCookie() {
        Map<String, String> requestCookieHeader =
                Map.of(
                        CookieHelper.REQUEST_COOKIE_HEADER,
                        "di-persistent-session-id=some-persistent-id;gs=session-id.456");

        String persistentSessionId =
                orchestrationAuthorizationService.getExistingOrCreateNewPersistentSessionId(
                        requestCookieHeader);

        assertTrue(isValidPersistentSessionCookieWithDoubleDashedTimestamp(persistentSessionId));
    }

    @Test
    void shouldConstructASignedAndEncryptedRequestJWT() {
        var claim1Value = "JWT claim 1";
        var jwtClaimsSet = new JWTClaimsSet.Builder().claim("claim1", claim1Value).build();

        orchestrationAuthorizationService.getSignedAndEncryptedJWT(jwtClaimsSet);

        verify(orchJwtService)
                .signAndEncryptJWT(jwtClaimsSet, SIGNING_KEY_ALIAS, publicEncryptionKey);
    }

    @Test
    void shouldSaveStateInDynamo() {
        when(configurationService.getSessionExpiry()).thenReturn(3600L);
        var sessionId = "new-session-id";
        var clientSessionId = "new-client-session-id";
        var state = new State();

        orchestrationAuthorizationService.storeState(sessionId, clientSessionId, state);

        var prefixedSessionId = "auth-state:" + sessionId;
        verify(stateStorageService).storeState(prefixedSessionId, state.getValue());
        verify(crossBrowserOrchestrationService)
                .storeClientSessionIdAgainstState(clientSessionId, state);
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldIdentifyIfJarValidationIsRequired(boolean isJarValidationRequired) {
        var clientReg =
                generateClientRegistry(REDIRECT_URI.toString(), CLIENT_ID.toString())
                        .withJarValidationRequired(isJarValidationRequired);
        when(dynamoClientService.getClient(CLIENT_ID.toString()))
                .thenReturn(Optional.of(clientReg));

        var response = orchestrationAuthorizationService.isJarValidationRequired(clientReg);
        assertThat(response, equalTo(isJarValidationRequired));
    }

    private ClientRegistry generateClientRegistry(String redirectURI, String clientID) {
        return generateClientRegistry(redirectURI, clientID, singletonList("openid"), false);
    }

    private ClientRegistry generateClientRegistry(
            String redirectURI, String clientID, List<String> scopes, boolean testClient) {
        return new ClientRegistry()
                .withRedirectUrls(singletonList(redirectURI))
                .withClientID(clientID)
                .withContacts(singletonList("joe.bloggs@digital.cabinet-office.gov.uk"))
                .withPublicKey(null)
                .withTestClient(testClient)
                .withScopes(scopes);
    }

    private AuthenticationRequest generateAuthRequest(
            String redirectUri, ResponseType responseType, Scope scope) {
        return generateAuthRequest(
                redirectUri, responseType, scope, jsonArrayOf("Cl.Cm", "Cl"), Optional.empty());
    }

    private AuthenticationRequest generateAuthRequest(
            String redirectUri,
            ResponseType responseType,
            Scope scope,
            String jsonArray,
            Optional<OIDCClaimsRequest> claimsRequest) {
        AuthenticationRequest.Builder authRequestBuilder =
                new AuthenticationRequest.Builder(
                                responseType, scope, CLIENT_ID, URI.create(redirectUri))
                        .state(STATE)
                        .nonce(NONCE)
                        .customParameter("vtr", jsonArray);
        claimsRequest.ifPresent(authRequestBuilder::claims);

        return authRequestBuilder.build();
    }
}
