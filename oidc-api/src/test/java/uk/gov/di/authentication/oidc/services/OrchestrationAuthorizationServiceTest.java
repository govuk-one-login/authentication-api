package uk.gov.di.authentication.oidc.services;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.oidc.entity.AuthRequestError;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.ClientType;
import uk.gov.di.authentication.shared.entity.CustomScopeValue;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoClientService;
import uk.gov.di.authentication.shared.services.KmsConnectionService;
import uk.gov.di.authentication.shared.services.RedisConnectionService;
import uk.gov.di.authentication.sharedtest.helper.JsonArrayHelper;
import uk.gov.di.authentication.sharedtest.helper.KeyPairHelper;

import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.oidc.helper.RequestObjectTestHelper.generateSignedJWT;

class OrchestrationAuthorizationServiceTest {

    private static final String REDIRECT_URI = "https://localhost:8080";

    private OrchestrationAuthorizationService service;
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final DynamoClientService dynamoClientService = mock(DynamoClientService.class);
    private final IPVCapacityService ipvCapacityService = mock(IPVCapacityService.class);

    private final KmsConnectionService kmsConnectionService = mock(KmsConnectionService.class);
    private final RedisConnectionService redisConnectionService =
            mock(RedisConnectionService.class);
    private KeyPair keyPair;
    private static final String DOC_APP_SCOPE = "openid doc-checking-app";
    private static final State STATE = new State();
    private static final Nonce NONCE = new Nonce();
    private static final ClientID CLIENT_ID = new ClientID("test-id");
    private static final String OIDC_BASE_URI = "https://localhost";
    private static final String AUDIENCE = "https://localhost/authorize";

    @BeforeEach
    void setup() {
        when(configurationService.getOidcApiBaseURL()).thenReturn(Optional.of(OIDC_BASE_URI));
        keyPair = KeyPairHelper.GENERATE_RSA_KEY_PAIR();
        service =
                new OrchestrationAuthorizationService(
                        configurationService,
                        dynamoClientService,
                        ipvCapacityService,
                        kmsConnectionService,
                        redisConnectionService);

        var clientRegistry =
                generateClientRegistry(
                        ClientType.APP.getValue(),
                        new Scope(
                                OIDCScopeValue.OPENID.getValue(),
                                CustomScopeValue.DOC_CHECKING_APP.getValue()));
        when(dynamoClientService.getClient(CLIENT_ID.getValue()))
                .thenReturn(Optional.of(clientRegistry));
    }

    @Test
    void shouldSuccessfullyProcessRequestUriPayload() throws JOSEException, ParseException {
        var jwtClaimsSet =
                new JWTClaimsSet.Builder()
                        .audience(AUDIENCE)
                        .claim("redirect_uri", REDIRECT_URI)
                        .claim("response_type", ResponseType.CODE.toString())
                        .claim("scope", DOC_APP_SCOPE)
                        .claim("nonce", NONCE.getValue())
                        .claim("state", STATE.toString())
                        .claim("client_id", CLIENT_ID.getValue())
                        .issuer(CLIENT_ID.getValue())
                        .build();
        var signedJWT = generateSignedJWT(jwtClaimsSet, keyPair);
        var authRequest = generateAuthRequestThatRequiresJar(signedJWT);
        var requestObjectError = service.validateAuthRequest(authRequest, false);

        assertThat(requestObjectError, equalTo(Optional.empty()));
    }

    @Test
    void shouldSuccessfullyProcessRequestUriPayloadWhenVtrIsPresent()
            throws JOSEException, ParseException {
        when(ipvCapacityService.isIPVCapacityAvailable()).thenReturn(true);
        var jwtClaimsSet =
                new JWTClaimsSet.Builder()
                        .audience(AUDIENCE)
                        .claim("redirect_uri", REDIRECT_URI)
                        .claim("response_type", ResponseType.CODE.toString())
                        .claim("scope", DOC_APP_SCOPE)
                        .claim("nonce", NONCE.getValue())
                        .claim("state", STATE.toString())
                        .claim("client_id", CLIENT_ID.getValue())
                        .claim("vtr", JsonArrayHelper.jsonArrayOf("P2.Cl.Cm"))
                        .issuer(CLIENT_ID.getValue())
                        .build();
        var signedJWT = generateSignedJWT(jwtClaimsSet, keyPair);
        var authRequest = generateAuthRequestThatRequiresJar(signedJWT);
        var requestObjectError = service.validateAuthRequest(authRequest, false);

        assertThat(requestObjectError, equalTo(Optional.empty()));
    }

    @Test
    void shouldThrowWhenRedirectUriIsInvalid() throws JOSEException {
        var jwtClaimsSet =
                new JWTClaimsSet.Builder()
                        .audience(AUDIENCE)
                        .claim("redirect_uri", "https://invalid-redirect-uri")
                        .claim("response_type", ResponseType.CODE.toString())
                        .claim("scope", DOC_APP_SCOPE)
                        .claim("nonce", NONCE.getValue())
                        .claim("state", STATE.toString())
                        .claim("client_id", CLIENT_ID.getValue())
                        .issuer(CLIENT_ID.getValue())
                        .build();
        var signedJWT = generateSignedJWT(jwtClaimsSet, keyPair);
        var authRequest = generateAuthRequestThatRequiresJar(signedJWT);

        assertRuntimeExceptionThrown(authRequest, "Invalid Redirect URI in request JWT");
    }

    @Test
    void shouldThrowWhenRedirectUriIsAbsent() throws JOSEException {
        var jwtClaimsSet =
                new JWTClaimsSet.Builder()
                        .audience(AUDIENCE)
                        .claim("response_type", ResponseType.CODE.toString())
                        .claim("scope", DOC_APP_SCOPE)
                        .claim("nonce", NONCE.getValue())
                        .claim("state", STATE.toString())
                        .claim("client_id", CLIENT_ID.getValue())
                        .issuer(CLIENT_ID.getValue())
                        .build();
        var signedJWT = generateSignedJWT(jwtClaimsSet, keyPair);
        var authRequest = generateAuthRequestThatRequiresJar(signedJWT);

        assertRuntimeExceptionThrown(authRequest, "Invalid Redirect URI in request JWT");
    }

    @Test
    void shouldThrowWhenInvalidClient() throws JOSEException {
        when(dynamoClientService.getClient(CLIENT_ID.getValue())).thenReturn(Optional.empty());
        var jwtClaimsSet =
                new JWTClaimsSet.Builder()
                        .audience(AUDIENCE)
                        .claim("redirect_uri", REDIRECT_URI)
                        .claim("response_type", ResponseType.CODE.toString())
                        .claim("scope", DOC_APP_SCOPE)
                        .claim("nonce", NONCE.getValue())
                        .claim("state", STATE.toString())
                        .claim("client_id", CLIENT_ID.getValue())
                        .issuer(CLIENT_ID.getValue())
                        .build();
        var signedJWT = generateSignedJWT(jwtClaimsSet, keyPair);
        var authRequest = generateAuthRequestThatRequiresJar(signedJWT);

        assertRuntimeExceptionThrown(authRequest, "No Client found with given ClientID");
    }

    @Test
    void shouldThrowErrorWhenRequestRequiresJARButRequestObjectIsEmpty() {
        Scope scope = Scope.parse(DOC_APP_SCOPE);
        AuthenticationRequest authRequest =
                new AuthenticationRequest.Builder(
                                ResponseType.CODE, scope, CLIENT_ID, URI.create(REDIRECT_URI))
                        .state(STATE)
                        .nonce(new Nonce())
                        .build();

        assertRuntimeExceptionThrown(
                authRequest, "JAR required but request does not contain Request Object");
    }

    @Test
    void shouldReturnErrorWhenClientTypeIsNotAppOrWeb() throws JOSEException, ParseException {
        var clientRegistry =
                generateClientRegistry(
                        "not-app-or-web",
                        new Scope(
                                OIDCScopeValue.OPENID.getValue(),
                                CustomScopeValue.DOC_CHECKING_APP.getValue()));
        when(dynamoClientService.getClient(CLIENT_ID.getValue()))
                .thenReturn(Optional.of(clientRegistry));
        var jwtClaimsSet =
                new JWTClaimsSet.Builder()
                        .audience(AUDIENCE)
                        .claim("redirect_uri", REDIRECT_URI)
                        .claim("response_type", ResponseType.CODE.toString())
                        .claim("scope", DOC_APP_SCOPE)
                        .claim("nonce", NONCE.getValue())
                        .claim("state", STATE.toString())
                        .claim("state", new State())
                        .claim("client_id", CLIENT_ID.getValue())
                        .issuer(CLIENT_ID.getValue())
                        .build();
        var signedJWT = generateSignedJWT(jwtClaimsSet, keyPair);
        var authRequest = generateAuthRequestThatRequiresJar(signedJWT);
        var requestObjectError = service.validateAuthRequest(authRequest, false);

        assertOAuthError(requestObjectError, OAuth2Error.UNAUTHORIZED_CLIENT, REDIRECT_URI);
    }

    @Test
    void shouldReturnErrorForInvalidResponseType() throws JOSEException, ParseException {
        var jwtClaimsSet =
                new JWTClaimsSet.Builder()
                        .audience(AUDIENCE)
                        .claim("redirect_uri", REDIRECT_URI)
                        .claim("response_type", ResponseType.CODE_IDTOKEN.toString())
                        .claim("scope", DOC_APP_SCOPE)
                        .claim("nonce", NONCE.getValue())
                        .claim("state", STATE.toString())
                        .issuer(CLIENT_ID.getValue())
                        .claim("client_id", CLIENT_ID.getValue())
                        .build();
        var signedJWT = generateSignedJWT(jwtClaimsSet, keyPair);
        var authRequest = generateAuthRequestThatRequiresJar(signedJWT);
        var requestObjectError = service.validateAuthRequest(authRequest, false);

        assertOAuthError(requestObjectError, OAuth2Error.UNSUPPORTED_RESPONSE_TYPE, REDIRECT_URI);
    }

    @Test
    void shouldReturnErrorForInvalidResponseTypeInQueryParams()
            throws JOSEException, ParseException {
        var jwtClaimsSet =
                new JWTClaimsSet.Builder()
                        .audience(AUDIENCE)
                        .claim("redirect_uri", REDIRECT_URI)
                        .claim("response_type", ResponseType.CODE.toString())
                        .claim("scope", DOC_APP_SCOPE)
                        .claim("nonce", NONCE.getValue())
                        .claim("state", STATE.toString())
                        .issuer(CLIENT_ID.getValue())
                        .claim("client_id", CLIENT_ID.getValue())
                        .build();

        var authRequest =
                new AuthenticationRequest.Builder(
                                generateSignedJWT(jwtClaimsSet, keyPair), CLIENT_ID)
                        .scope(new Scope(Scope.parse(DOC_APP_SCOPE)))
                        .responseType(ResponseType.IDTOKEN)
                        .build();
        var requestObjectError = service.validateAuthRequest(authRequest, false);

        assertOAuthError(requestObjectError, OAuth2Error.UNSUPPORTED_RESPONSE_TYPE, REDIRECT_URI);
    }

    @Test
    void shouldReturnErrorWhenClientIDIsInvalid() throws JOSEException, ParseException {
        var jwtClaimsSet =
                new JWTClaimsSet.Builder()
                        .audience(AUDIENCE)
                        .claim("redirect_uri", REDIRECT_URI)
                        .claim("response_type", ResponseType.CODE.toString())
                        .claim("scope", DOC_APP_SCOPE)
                        .claim("nonce", NONCE.getValue())
                        .claim("state", STATE.toString())
                        .issuer(CLIENT_ID.getValue())
                        .claim("client_id", "invalid-client-id")
                        .build();
        var signedJWT = generateSignedJWT(jwtClaimsSet, keyPair);
        var authRequest = generateAuthRequestThatRequiresJar(signedJWT);
        var requestObjectError = service.validateAuthRequest(authRequest, false);

        assertOAuthError(requestObjectError, OAuth2Error.UNAUTHORIZED_CLIENT, REDIRECT_URI);
    }

    @Test
    void shouldReturnErrorForUnsupportedScope() throws JOSEException, ParseException {
        var jwtClaimsSet =
                new JWTClaimsSet.Builder()
                        .audience(AUDIENCE)
                        .claim("redirect_uri", REDIRECT_URI)
                        .claim("response_type", ResponseType.CODE.toString())
                        .claim("scope", "openid profile")
                        .claim("nonce", NONCE.getValue())
                        .claim("state", STATE.toString())
                        .claim("client_id", CLIENT_ID.getValue())
                        .issuer(CLIENT_ID.getValue())
                        .build();
        var signedJWT = generateSignedJWT(jwtClaimsSet, keyPair);
        var authRequest = generateAuthRequestThatRequiresJar(signedJWT);
        var requestObjectError = service.validateAuthRequest(authRequest, false);

        assertOAuthError(requestObjectError, OAuth2Error.INVALID_SCOPE, REDIRECT_URI);
    }

    @Test
    void shouldReturnErrorWhenClientHasNotRegisteredDocAppScope()
            throws JOSEException, ParseException {
        var clientRegistry =
                generateClientRegistry(
                        ClientType.APP.getValue(), new Scope(OIDCScopeValue.OPENID.getValue()));
        when(dynamoClientService.getClient(CLIENT_ID.getValue()))
                .thenReturn(Optional.of(clientRegistry));

        var jwtClaimsSet =
                new JWTClaimsSet.Builder()
                        .audience(AUDIENCE)
                        .claim("redirect_uri", REDIRECT_URI)
                        .claim("response_type", ResponseType.CODE.toString())
                        .claim("scope", DOC_APP_SCOPE)
                        .claim("nonce", NONCE.getValue())
                        .claim("state", STATE.toString())
                        .claim("client_id", CLIENT_ID.getValue())
                        .issuer(CLIENT_ID.getValue())
                        .build();
        var signedJWT = generateSignedJWT(jwtClaimsSet, keyPair);
        var authRequest = generateAuthRequestThatRequiresJar(signedJWT);
        var requestObjectError = service.validateAuthRequest(authRequest, false);

        assertOAuthError(requestObjectError, OAuth2Error.INVALID_SCOPE, REDIRECT_URI);
    }

    @Test
    void shouldReturnErrorWhenInvalidScopeInRequestObject() throws JOSEException, ParseException {
        List<String> scopes = new ArrayList<>();
        scopes.add("openid");
        scopes.add("doc-checking-app");
        scopes.add("email");
        var scope = Scope.parse(scopes);
        var jwtClaimsSet =
                new JWTClaimsSet.Builder()
                        .audience(AUDIENCE)
                        .claim("redirect_uri", REDIRECT_URI)
                        .claim("response_type", ResponseType.CODE.toString())
                        .claim("scope", scope)
                        .claim("nonce", NONCE.getValue())
                        .claim("state", STATE.getValue())
                        .claim("client_id", CLIENT_ID.getValue())
                        .issuer(CLIENT_ID.getValue())
                        .build();
        var signedJWT = generateSignedJWT(jwtClaimsSet, keyPair);
        var authRequest = generateAuthRequestThatRequiresJar(signedJWT);
        var requestObjectError = service.validateAuthRequest(authRequest, false);

        assertOAuthError(requestObjectError, OAuth2Error.INVALID_SCOPE, REDIRECT_URI);
    }

    @Test
    void shouldReturnErrorForUnregisteredScope() throws JOSEException, ParseException {
        var jwtClaimsSet =
                new JWTClaimsSet.Builder()
                        .audience(AUDIENCE)
                        .claim("redirect_uri", REDIRECT_URI)
                        .claim("response_type", ResponseType.CODE.toString())
                        .claim("scope", "openid email")
                        .claim("nonce", NONCE.getValue())
                        .claim("state", STATE.getValue())
                        .claim("client_id", CLIENT_ID.getValue())
                        .issuer(CLIENT_ID.getValue())
                        .build();
        var signedJWT = generateSignedJWT(jwtClaimsSet, keyPair);
        var authRequest = generateAuthRequestThatRequiresJar(signedJWT);
        var requestObjectError = service.validateAuthRequest(authRequest, false);

        assertOAuthError(requestObjectError, OAuth2Error.INVALID_SCOPE, REDIRECT_URI);
    }

    @Test
    void shouldReturnErrorForInvalidAudience() throws JOSEException, ParseException {
        var jwtClaimsSet =
                new JWTClaimsSet.Builder()
                        .audience("invalid-audience")
                        .claim("redirect_uri", REDIRECT_URI)
                        .claim("response_type", ResponseType.CODE.toString())
                        .claim("scope", "openid")
                        .claim("nonce", NONCE.getValue())
                        .claim("state", STATE.getValue())
                        .claim("client_id", CLIENT_ID.getValue())
                        .issuer(CLIENT_ID.getValue())
                        .build();

        var signedJWT = generateSignedJWT(jwtClaimsSet, keyPair);
        var authRequest = generateAuthRequestThatRequiresJar(signedJWT);
        var requestObjectError = service.validateAuthRequest(authRequest, false);

        assertOAuthError(requestObjectError, OAuth2Error.ACCESS_DENIED, REDIRECT_URI);
    }

    @Test
    void shouldReturnErrorForInvalidIssuer() throws JOSEException, ParseException {
        var jwtClaimsSet =
                new JWTClaimsSet.Builder()
                        .audience(AUDIENCE)
                        .claim("redirect_uri", REDIRECT_URI)
                        .claim("response_type", ResponseType.CODE.toString())
                        .claim("scope", "openid")
                        .claim("nonce", NONCE.getValue())
                        .claim("state", STATE.getValue())
                        .claim("client_id", CLIENT_ID.getValue())
                        .issuer("invalid-client")
                        .build();
        var signedJWT = generateSignedJWT(jwtClaimsSet, keyPair);
        var authRequest = generateAuthRequestThatRequiresJar(signedJWT);
        var requestObjectError = service.validateAuthRequest(authRequest, false);

        assertOAuthError(requestObjectError, OAuth2Error.UNAUTHORIZED_CLIENT, REDIRECT_URI);
    }

    @Test
    void shouldReturnErrorIfRequestClaimIsPresentInRequestObject()
            throws JOSEException, ParseException {
        var jwtClaimsSet =
                new JWTClaimsSet.Builder()
                        .audience(AUDIENCE)
                        .claim("redirect_uri", REDIRECT_URI)
                        .claim("response_type", ResponseType.CODE.toString())
                        .claim("scope", "openid")
                        .claim("nonce", NONCE.getValue())
                        .claim("state", STATE.getValue())
                        .claim("client_id", CLIENT_ID.getValue())
                        .claim("request", "some-random-request-value")
                        .issuer(CLIENT_ID.getValue())
                        .build();
        var signedJWT = generateSignedJWT(jwtClaimsSet, keyPair);
        var authRequest = generateAuthRequestThatRequiresJar(signedJWT);
        var requestObjectError = service.validateAuthRequest(authRequest, false);

        assertOAuthError(requestObjectError, OAuth2Error.INVALID_REQUEST, REDIRECT_URI);
    }

    @Test
    void shouldReturnErrorIfRequestUriClaimIsPresentInRequestObject()
            throws JOSEException, ParseException {
        var jwtClaimsSet =
                new JWTClaimsSet.Builder()
                        .audience(AUDIENCE)
                        .claim("redirect_uri", REDIRECT_URI)
                        .claim("response_type", ResponseType.CODE.toString())
                        .claim("scope", DOC_APP_SCOPE)
                        .claim("nonce", NONCE.getValue())
                        .claim("state", STATE.getValue())
                        .claim("client_id", CLIENT_ID.getValue())
                        .claim("request_uri", URI.create("https://localhost/request_uri"))
                        .issuer(CLIENT_ID.getValue())
                        .build();
        var signedJWT = generateSignedJWT(jwtClaimsSet, keyPair);
        var authRequest = generateAuthRequestThatRequiresJar(signedJWT);
        var requestObjectError = service.validateAuthRequest(authRequest, false);

        assertOAuthError(requestObjectError, OAuth2Error.INVALID_REQUEST, REDIRECT_URI);
    }

    @Test
    void shouldThrowWhenUnableToValidateRequestObjectSignature()
            throws JOSEException, NoSuchAlgorithmException {
        var keyPair2 = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        var jwtClaimsSet =
                new JWTClaimsSet.Builder()
                        .audience(AUDIENCE)
                        .claim("redirect_uri", REDIRECT_URI)
                        .claim("response_type", ResponseType.CODE.toString())
                        .claim("scope", DOC_APP_SCOPE)
                        .claim("nonce", NONCE.getValue())
                        .claim("state", STATE.getValue())
                        .claim("client_id", CLIENT_ID.getValue())
                        .issuer(CLIENT_ID.getValue())
                        .build();
        var signedJWT = generateSignedJWT(jwtClaimsSet, keyPair2);
        var authRequest = generateAuthRequestThatRequiresJar(signedJWT);

        assertRuntimeExceptionThrown(authRequest, "Invalid Signature on request JWT");
    }

    @Test
    void shouldReturnErrorIfStateIsMissingFromRequestObject() throws JOSEException, ParseException {
        var jwtClaimsSet =
                new JWTClaimsSet.Builder()
                        .audience(AUDIENCE)
                        .claim("redirect_uri", REDIRECT_URI)
                        .claim("response_type", ResponseType.CODE.toString())
                        .claim("scope", DOC_APP_SCOPE)
                        .claim("nonce", NONCE.getValue())
                        .claim("client_id", CLIENT_ID.getValue())
                        .issuer(CLIENT_ID.getValue())
                        .build();
        var signedJWT = generateSignedJWT(jwtClaimsSet, keyPair);
        var authRequest = generateAuthRequestThatRequiresJar(signedJWT);
        var requestObjectError = service.validateAuthRequest(authRequest, false);

        assertOAuthError(requestObjectError, OAuth2Error.INVALID_REQUEST, REDIRECT_URI);
        assertThat(
                requestObjectError.get().errorObject().getDescription(),
                equalTo("Request is missing state parameter"));
    }

    @Test
    void shouldReturnErrorIfNonceIsMissingFromRequestObject() throws JOSEException, ParseException {
        var jwtClaimsSet =
                new JWTClaimsSet.Builder()
                        .audience(AUDIENCE)
                        .claim("redirect_uri", REDIRECT_URI)
                        .claim("response_type", ResponseType.CODE.toString())
                        .claim("scope", DOC_APP_SCOPE)
                        .claim("state", STATE.getValue())
                        .claim("client_id", CLIENT_ID.getValue())
                        .issuer(CLIENT_ID.getValue())
                        .build();
        var signedJWT = generateSignedJWT(jwtClaimsSet, keyPair);
        var authRequest = generateAuthRequestThatRequiresJar(signedJWT);
        var requestObjectError = service.validateAuthRequest(authRequest, false);

        assertOAuthError(requestObjectError, OAuth2Error.INVALID_REQUEST, REDIRECT_URI);
        assertThat(
                requestObjectError.get().errorObject().getDescription(),
                equalTo("Request is missing nonce parameter"));
    }

    @Test
    void shouldReturnErrorForInvalidUILocales() throws JOSEException, ParseException {
        var jwtClaimsSet =
                new JWTClaimsSet.Builder()
                        .audience(AUDIENCE)
                        .claim("redirect_uri", REDIRECT_URI)
                        .claim("response_type", ResponseType.CODE.toString())
                        .claim("scope", DOC_APP_SCOPE)
                        .claim("nonce", NONCE.getValue())
                        .claim("state", STATE.toString())
                        .issuer(CLIENT_ID.getValue())
                        .claim("client_id", CLIENT_ID.getValue())
                        .claim("ui_locales", "123456")
                        .build();
        var signedJWT = generateSignedJWT(jwtClaimsSet, keyPair);
        var authRequest = generateAuthRequestThatRequiresJar(signedJWT);
        var requestObjectError = service.validateAuthRequest(authRequest, false);

        assertOAuthError(requestObjectError, OAuth2Error.INVALID_REQUEST, REDIRECT_URI);
    }

    private ClientRegistry generateClientRegistry(String clientType, Scope scope) {
        return new ClientRegistry()
                .withClientID(CLIENT_ID.getValue())
                .withPublicKey(
                        Base64.getMimeEncoder().encodeToString(keyPair.getPublic().getEncoded()))
                .withConsentRequired(false)
                .withClientName("test-client")
                .withScopes(scope.toStringList())
                .withRedirectUrls(singletonList(REDIRECT_URI))
                .withSectorIdentifierUri("https://test.com")
                .withSubjectType("pairwise")
                .withClientType(clientType);
    }

    private AuthenticationRequest generateAuthRequestThatDoesNotRequireJar(SignedJWT signedJWT) {
        return generateAuthRequest(signedJWT, new Scope(OIDCScopeValue.OPENID));
    }

    private AuthenticationRequest generateAuthRequestThatRequiresJar(SignedJWT signedJWT) {
        var scope = Scope.parse(DOC_APP_SCOPE);
        return generateAuthRequest(signedJWT, new Scope(scope));
    }

    private AuthenticationRequest generateAuthRequest(SignedJWT signedJWT, Scope scope) {
        AuthenticationRequest.Builder builder =
                new AuthenticationRequest.Builder(signedJWT, CLIENT_ID)
                        .scope(scope)
                        .responseType(ResponseType.CODE);
        return builder.build();
    }

    private void assertRuntimeExceptionThrown(AuthenticationRequest authRequest, String message) {
        RuntimeException expectedException =
                assertThrows(
                        RuntimeException.class,
                        () -> service.validateAuthRequest(authRequest, false),
                        "Expected to throw exception");
        assertThat(expectedException.getMessage(), equalTo(message));
    }

    private void assertOAuthError(
            Optional<AuthRequestError> requestObjectError,
            ErrorObject errorObject,
            String redirectUri) {
        assertTrue(requestObjectError.isPresent());
        assertThat(requestObjectError.get().errorObject(), equalTo(errorObject));
        assertThat(requestObjectError.get().redirectURI().toString(), equalTo(redirectUri));
    }
}
