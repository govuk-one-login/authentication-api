package uk.gov.di.authentication.oidc.services;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
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
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.ClientType;
import uk.gov.di.authentication.shared.entity.CustomScopeValue;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoClientService;
import uk.gov.di.authentication.sharedtest.helper.JsonArrayHelper;
import uk.gov.di.authentication.sharedtest.helper.KeyPairHelper;

import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.params.provider.Arguments.arguments;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.oidc.helper.RequestObjectTestHelper.generateSignedJWT;

class RequestObjectServiceTest {

    private static final String REDIRECT_URI = "https://localhost:8080";
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final DynamoClientService dynamoClientService = mock(DynamoClientService.class);
    private final IPVCapacityService ipvCapacityService = mock(IPVCapacityService.class);
    private static final String SCOPE = "openid doc-checking-app";
    private static final State STATE = new State();
    private static final Nonce NONCE = new Nonce();
    private static final ClientID CLIENT_ID = new ClientID("test-id");
    private static final String OIDC_BASE_URI = "https://localhost";
    private static final String AUDIENCE = "https://localhost/authorize";
    private static final KeyPair rsaKeyPair = KeyPairHelper.generateRsaKeyPair();
    private RequestObjectService service;

    @BeforeEach
    void setup() {
        when(configurationService.getOidcApiBaseURL()).thenReturn(Optional.of(OIDC_BASE_URI));

        service =
                new RequestObjectService(
                        dynamoClientService, configurationService, ipvCapacityService);
        var clientRegistry =
                generateClientRegistry(
                        ClientType.APP.getValue(),
                        new Scope(
                                OIDCScopeValue.OPENID.getValue(),
                                CustomScopeValue.DOC_CHECKING_APP.getValue()));
        when(dynamoClientService.getClient(CLIENT_ID.getValue()))
                .thenReturn(Optional.of(clientRegistry));
    }

    private static Stream<Arguments> supportedAlgorithms() {
        return Stream.of(
                arguments(JWSAlgorithm.RS256, rsaKeyPair),
                arguments(JWSAlgorithm.RS384, rsaKeyPair),
                arguments(JWSAlgorithm.RS512, rsaKeyPair),
                arguments(JWSAlgorithm.PS256, rsaKeyPair),
                arguments(JWSAlgorithm.PS384, rsaKeyPair),
                arguments(JWSAlgorithm.PS512, rsaKeyPair),
                arguments(
                        JWSAlgorithm.ES256,
                        KeyPairHelper.generateRsaOrEcKeyPair(JWSAlgorithm.ES256)),
                arguments(
                        JWSAlgorithm.ES384,
                        KeyPairHelper.generateRsaOrEcKeyPair(JWSAlgorithm.ES384)),
                arguments(
                        JWSAlgorithm.ES512,
                        KeyPairHelper.generateRsaOrEcKeyPair(JWSAlgorithm.ES512)));
    }

    @ParameterizedTest
    @MethodSource("supportedAlgorithms")
    void shouldSuccessfullyProcessRequestUriPayload(JWSAlgorithm algorithm, KeyPair keyPair)
            throws JOSEException {
        var clientRegistry =
                generateClientRegistry(
                        ClientType.APP.getValue(),
                        new Scope(
                                OIDCScopeValue.OPENID.getValue(),
                                CustomScopeValue.DOC_CHECKING_APP.getValue()),
                        keyPair.getPublic());
        when(dynamoClientService.getClient(CLIENT_ID.getValue()))
                .thenReturn(Optional.of(clientRegistry));

        List<String> scopes = new ArrayList<>();
        scopes.add("openid");
        scopes.add("doc-checking-app");
        var scope = Scope.parse(scopes);
        var jwtClaimsSet =
                new JWTClaimsSet.Builder()
                        .audience(AUDIENCE)
                        .claim("redirect_uri", REDIRECT_URI)
                        .claim("response_type", ResponseType.CODE.toString())
                        .claim("scope", scope.toString())
                        .claim("nonce", NONCE.getValue())
                        .claim("state", STATE.toString())
                        .claim("client_id", CLIENT_ID.getValue())
                        .issuer(CLIENT_ID.getValue())
                        .build();
        var signedJWT = generateSignedJWT(jwtClaimsSet, keyPair, algorithm);

        var requestObjectError = service.validateRequestObject(generateAuthRequest(signedJWT));

        assertThat(requestObjectError, equalTo(Optional.empty()));
    }

    @Test
    void shouldSuccessfullyProcessRequestUriPayloadWhenVtrIsPresent() throws JOSEException {
        when(ipvCapacityService.isIPVCapacityAvailable()).thenReturn(true);
        List<String> scopes = new ArrayList<>();
        scopes.add("openid");
        scopes.add("doc-checking-app");
        var scope = Scope.parse(scopes);
        var jwtClaimsSet =
                new JWTClaimsSet.Builder()
                        .audience(AUDIENCE)
                        .claim("redirect_uri", REDIRECT_URI)
                        .claim("response_type", ResponseType.CODE.toString())
                        .claim("scope", scope.toString())
                        .claim("nonce", NONCE.getValue())
                        .claim("state", STATE.toString())
                        .claim("client_id", CLIENT_ID.getValue())
                        .claim("vtr", JsonArrayHelper.jsonArrayOf("P2.Cl.Cm"))
                        .issuer(CLIENT_ID.getValue())
                        .build();
        var signedJWT = generateSignedJWT(jwtClaimsSet, rsaKeyPair);

        var requestObjectError = service.validateRequestObject(generateAuthRequest(signedJWT));

        assertThat(requestObjectError, equalTo(Optional.empty()));
    }

    @Test
    void shouldThrowWhenRedirectUriIsInvalid() throws JOSEException {
        var jwtClaimsSet =
                new JWTClaimsSet.Builder()
                        .audience(AUDIENCE)
                        .claim("redirect_uri", "https://invalid-redirect-uri")
                        .claim("response_type", ResponseType.CODE.toString())
                        .claim("scope", SCOPE)
                        .claim("nonce", NONCE.getValue())
                        .claim("state", STATE.toString())
                        .claim("client_id", CLIENT_ID.getValue())
                        .issuer(CLIENT_ID.getValue())
                        .build();
        var authRequest = generateAuthRequest(generateSignedJWT(jwtClaimsSet, rsaKeyPair));
        assertThrows(
                RuntimeException.class,
                () -> service.validateRequestObject(authRequest),
                "Expected to throw exception");
    }

    @Test
    void shouldThrowWhenInvalidClient() throws JOSEException {
        when(dynamoClientService.getClient(CLIENT_ID.getValue())).thenReturn(Optional.empty());
        var jwtClaimsSet =
                new JWTClaimsSet.Builder()
                        .audience(AUDIENCE)
                        .claim("redirect_uri", REDIRECT_URI)
                        .claim("response_type", ResponseType.CODE.toString())
                        .claim("scope", SCOPE)
                        .claim("nonce", NONCE.getValue())
                        .claim("state", STATE.toString())
                        .claim("client_id", CLIENT_ID.getValue())
                        .issuer(CLIENT_ID.getValue())
                        .build();
        var signedJWT = generateSignedJWT(jwtClaimsSet, rsaKeyPair);

        assertThrows(
                RuntimeException.class,
                () -> service.validateRequestObject(generateAuthRequest(signedJWT)),
                "Expected to throw exception");
    }

    @Test
    void shouldReturnErrorWhenClientTypeIsNotApp() throws JOSEException {
        var clientRegistry =
                generateClientRegistry(
                        ClientType.WEB.getValue(),
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
                        .claim("scope", SCOPE)
                        .claim("nonce", NONCE.getValue())
                        .claim("state", STATE.toString())
                        .claim("state", new State())
                        .claim("client_id", CLIENT_ID.getValue())
                        .issuer(CLIENT_ID.getValue())
                        .build();
        var signedJWT = generateSignedJWT(jwtClaimsSet, rsaKeyPair);

        var requestObjectError = service.validateRequestObject(generateAuthRequest(signedJWT));

        assertTrue(requestObjectError.isPresent());
        assertThat(
                requestObjectError.get().getErrorObject(),
                equalTo(OAuth2Error.UNAUTHORIZED_CLIENT));
        assertThat(requestObjectError.get().getRedirectURI().toString(), equalTo(REDIRECT_URI));
    }

    @Test
    void shouldReturnErrorForInvalidResponseType() throws JOSEException {
        var jwtClaimsSet =
                new JWTClaimsSet.Builder()
                        .audience(AUDIENCE)
                        .claim("redirect_uri", REDIRECT_URI)
                        .claim("response_type", ResponseType.CODE_IDTOKEN.toString())
                        .claim("scope", SCOPE)
                        .claim("nonce", NONCE.getValue())
                        .claim("state", STATE.toString())
                        .issuer(CLIENT_ID.getValue())
                        .claim("client_id", CLIENT_ID.getValue())
                        .build();
        var authRequest = generateAuthRequest(generateSignedJWT(jwtClaimsSet, rsaKeyPair));
        var requestObjectError = service.validateRequestObject(authRequest);

        assertTrue(requestObjectError.isPresent());
        assertThat(
                requestObjectError.get().getErrorObject(),
                equalTo(OAuth2Error.UNSUPPORTED_RESPONSE_TYPE));
        assertThat(requestObjectError.get().getRedirectURI().toString(), equalTo(REDIRECT_URI));
    }

    @Test
    void shouldReturnErrorWhenClientIDIsInvalid() throws JOSEException {
        var jwtClaimsSet =
                new JWTClaimsSet.Builder()
                        .audience(AUDIENCE)
                        .claim("redirect_uri", REDIRECT_URI)
                        .claim("response_type", ResponseType.CODE.toString())
                        .claim("scope", SCOPE)
                        .claim("nonce", NONCE.getValue())
                        .claim("state", STATE.toString())
                        .issuer(CLIENT_ID.getValue())
                        .claim("client_id", "invalid-client-id")
                        .build();
        var authRequest = generateAuthRequest(generateSignedJWT(jwtClaimsSet, rsaKeyPair));
        var requestObjectError = service.validateRequestObject(authRequest);

        assertTrue(requestObjectError.isPresent());
        assertThat(
                requestObjectError.get().getErrorObject(),
                equalTo(OAuth2Error.UNAUTHORIZED_CLIENT));
        assertThat(requestObjectError.get().getRedirectURI().toString(), equalTo(REDIRECT_URI));
    }

    @Test
    void shouldReturnErrorForUnsupportedScope() throws JOSEException {
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
        var authRequest = generateAuthRequest(generateSignedJWT(jwtClaimsSet, rsaKeyPair));
        var requestObjectError = service.validateRequestObject(authRequest);

        assertTrue(requestObjectError.isPresent());
        assertThat(requestObjectError.get().getErrorObject(), equalTo(OAuth2Error.INVALID_SCOPE));
        assertThat(requestObjectError.get().getRedirectURI().toString(), equalTo(REDIRECT_URI));
    }

    @Test
    void shouldReturnErrorWhenRequestObjectDoesNotContainDocAppScope() throws JOSEException {
        var jwtClaimsSet =
                new JWTClaimsSet.Builder()
                        .audience(AUDIENCE)
                        .claim("redirect_uri", REDIRECT_URI)
                        .claim("response_type", ResponseType.CODE.toString())
                        .claim("scope", "openid")
                        .claim("nonce", NONCE.getValue())
                        .claim("state", STATE.toString())
                        .claim("client_id", CLIENT_ID.getValue())
                        .issuer(CLIENT_ID.getValue())
                        .build();
        var authRequest = generateAuthRequest(generateSignedJWT(jwtClaimsSet, rsaKeyPair));
        var requestObjectError = service.validateRequestObject(authRequest);

        assertTrue(requestObjectError.isPresent());
        assertThat(requestObjectError.get().getErrorObject(), equalTo(OAuth2Error.INVALID_SCOPE));
        assertThat(requestObjectError.get().getRedirectURI().toString(), equalTo(REDIRECT_URI));
    }

    @Test
    void shouldReturnErrorWhenClientHasNotRegisteredDocAppScope() throws JOSEException {
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
                        .claim("scope", SCOPE)
                        .claim("nonce", NONCE.getValue())
                        .claim("state", STATE.toString())
                        .claim("client_id", CLIENT_ID.getValue())
                        .issuer(CLIENT_ID.getValue())
                        .build();
        var signedJWT = generateSignedJWT(jwtClaimsSet, rsaKeyPair);

        var requestObjectError = service.validateRequestObject(generateAuthRequest(signedJWT));

        assertTrue(requestObjectError.isPresent());
        assertThat(requestObjectError.get().getErrorObject(), equalTo(OAuth2Error.INVALID_SCOPE));
        assertThat(requestObjectError.get().getRedirectURI().toString(), equalTo(REDIRECT_URI));
    }

    @Test
    void shouldReturnErrorWhenAuthRequestContainsInvalidScope() throws JOSEException {
        var jwtClaimsSet =
                new JWTClaimsSet.Builder()
                        .audience(AUDIENCE)
                        .claim("redirect_uri", REDIRECT_URI)
                        .claim("response_type", ResponseType.CODE.toString())
                        .claim("scope", SCOPE)
                        .claim("nonce", NONCE.getValue())
                        .claim("state", STATE.getValue())
                        .claim("client_id", CLIENT_ID.getValue())
                        .issuer(CLIENT_ID.getValue())
                        .build();
        var signedJWT = generateSignedJWT(jwtClaimsSet, rsaKeyPair);

        var requestObjectError =
                service.validateRequestObject(
                        generateAuthRequest(
                                signedJWT, new Scope(OIDCScopeValue.OPENID, OIDCScopeValue.EMAIL)));

        assertTrue(requestObjectError.isPresent());
        assertThat(requestObjectError.get().getErrorObject(), equalTo(OAuth2Error.INVALID_SCOPE));
        assertThat(requestObjectError.get().getRedirectURI().toString(), equalTo(REDIRECT_URI));
    }

    @Test
    void shouldReturnErrorForUnregisteredScope() throws JOSEException {
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
        var authRequest = generateAuthRequest(generateSignedJWT(jwtClaimsSet, rsaKeyPair));
        var requestObjectError = service.validateRequestObject(authRequest);

        assertTrue(requestObjectError.isPresent());
        assertThat(requestObjectError.get().getErrorObject(), equalTo(OAuth2Error.INVALID_SCOPE));
        assertThat(requestObjectError.get().getRedirectURI().toString(), equalTo(REDIRECT_URI));
    }

    @Test
    void shouldReturnErrorForInvalidAudience() throws JOSEException {
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

        var authRequest = generateAuthRequest(generateSignedJWT(jwtClaimsSet, rsaKeyPair));
        var requestObjectError = service.validateRequestObject(authRequest);

        assertTrue(requestObjectError.isPresent());
        assertThat(requestObjectError.get().getErrorObject(), equalTo(OAuth2Error.ACCESS_DENIED));
        assertThat(requestObjectError.get().getRedirectURI().toString(), equalTo(REDIRECT_URI));
    }

    @Test
    void shouldReturnErrorForInvalidIssuer() throws JOSEException {
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
        var authRequest = generateAuthRequest(generateSignedJWT(jwtClaimsSet, rsaKeyPair));
        var requestObjectError = service.validateRequestObject(authRequest);

        assertTrue(requestObjectError.isPresent());
        assertThat(
                requestObjectError.get().getErrorObject(),
                equalTo(OAuth2Error.UNAUTHORIZED_CLIENT));
        assertThat(requestObjectError.get().getRedirectURI().toString(), equalTo(REDIRECT_URI));
    }

    @Test
    void shouldReturnErrorIfRequestClaimIsPresentJwt() throws JOSEException {
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
        generateSignedJWT(jwtClaimsSet, rsaKeyPair);
        var authRequest = generateAuthRequest(generateSignedJWT(jwtClaimsSet, rsaKeyPair));
        var requestObjectError = service.validateRequestObject(authRequest);

        assertTrue(requestObjectError.isPresent());
        assertThat(requestObjectError.get().getErrorObject(), equalTo(OAuth2Error.INVALID_REQUEST));
        assertThat(requestObjectError.get().getRedirectURI().toString(), equalTo(REDIRECT_URI));
    }

    @Test
    void shouldReturnErrorIfRequestUriClaimIsPresentJwt() throws JOSEException {
        var jwtClaimsSet =
                new JWTClaimsSet.Builder()
                        .audience(AUDIENCE)
                        .claim("redirect_uri", REDIRECT_URI)
                        .claim("response_type", ResponseType.CODE.toString())
                        .claim("scope", "openid")
                        .claim("nonce", NONCE.getValue())
                        .claim("state", STATE.getValue())
                        .claim("client_id", CLIENT_ID.getValue())
                        .claim("request_uri", URI.create("https://localhost/request_uri"))
                        .issuer(CLIENT_ID.getValue())
                        .build();
        var authRequest = generateAuthRequest(generateSignedJWT(jwtClaimsSet, rsaKeyPair));
        var requestObjectError = service.validateRequestObject(authRequest);

        assertTrue(requestObjectError.isPresent());
        assertThat(requestObjectError.get().getErrorObject(), equalTo(OAuth2Error.INVALID_REQUEST));
        assertThat(requestObjectError.get().getRedirectURI().toString(), equalTo(REDIRECT_URI));
    }

    @Test
    void shouldThrowWhenUnableToValidateRequestJwtSignature()
            throws JOSEException, NoSuchAlgorithmException {
        var keyPair2 = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        var jwtClaimsSet =
                new JWTClaimsSet.Builder()
                        .audience(AUDIENCE)
                        .claim("redirect_uri", REDIRECT_URI)
                        .claim("response_type", ResponseType.CODE.toString())
                        .claim("scope", SCOPE)
                        .claim("nonce", NONCE.getValue())
                        .claim("state", STATE.getValue())
                        .claim("client_id", CLIENT_ID.getValue())
                        .issuer(CLIENT_ID.getValue())
                        .build();
        var authRequest = generateAuthRequest(generateSignedJWT(jwtClaimsSet, keyPair2));
        assertThrows(
                RuntimeException.class,
                () -> service.validateRequestObject(authRequest),
                "Expected to throw exception");
    }

    @Test
    void shouldReturnErrorIfStateIsMissingFromRequestObject() throws JOSEException {
        var jwtClaimsSet =
                new JWTClaimsSet.Builder()
                        .audience(AUDIENCE)
                        .claim("redirect_uri", REDIRECT_URI)
                        .claim("response_type", ResponseType.CODE.toString())
                        .claim("scope", SCOPE)
                        .claim("nonce", NONCE.getValue())
                        .claim("client_id", CLIENT_ID.getValue())
                        .issuer(CLIENT_ID.getValue())
                        .build();
        var signedJWT = generateSignedJWT(jwtClaimsSet, rsaKeyPair);

        var requestObjectError = service.validateRequestObject(generateAuthRequest(signedJWT));

        assertTrue(requestObjectError.isPresent());
        assertThat(requestObjectError.get().getErrorObject(), equalTo(OAuth2Error.INVALID_REQUEST));
        assertThat(
                requestObjectError.get().getErrorObject().getDescription(),
                equalTo("Request is missing state parameter"));
        assertThat(requestObjectError.get().getRedirectURI().toString(), equalTo(REDIRECT_URI));
    }

    @Test
    void shouldReturnErrorIfNonceIsMissingFromRequestObject() throws JOSEException {
        var jwtClaimsSet =
                new JWTClaimsSet.Builder()
                        .audience(AUDIENCE)
                        .claim("redirect_uri", REDIRECT_URI)
                        .claim("response_type", ResponseType.CODE.toString())
                        .claim("scope", SCOPE)
                        .claim("state", STATE.getValue())
                        .claim("client_id", CLIENT_ID.getValue())
                        .issuer(CLIENT_ID.getValue())
                        .build();
        var signedJWT = generateSignedJWT(jwtClaimsSet, rsaKeyPair);

        var requestObjectError = service.validateRequestObject(generateAuthRequest(signedJWT));

        assertTrue(requestObjectError.isPresent());
        assertThat(requestObjectError.get().getErrorObject(), equalTo(OAuth2Error.INVALID_REQUEST));
        assertThat(
                requestObjectError.get().getErrorObject().getDescription(),
                equalTo("Request is missing nonce parameter"));
        assertThat(requestObjectError.get().getRedirectURI().toString(), equalTo(REDIRECT_URI));
    }

    private ClientRegistry generateClientRegistry(
            String clientType, Scope scope, PublicKey publicKey) {
        return new ClientRegistry()
                .withClientID(CLIENT_ID.getValue())
                .withPublicKey(Base64.getMimeEncoder().encodeToString(publicKey.getEncoded()))
                .withConsentRequired(false)
                .withClientName("test-client")
                .withScopes(scope.toStringList())
                .withRedirectUrls(singletonList(REDIRECT_URI))
                .withSectorIdentifierUri("https://test.com")
                .withSubjectType("pairwise")
                .withClientType(clientType);
    }

    private ClientRegistry generateClientRegistry(String clientType, Scope scope) {
        return this.generateClientRegistry(clientType, scope, rsaKeyPair.getPublic());
    }

    private AuthenticationRequest generateAuthRequest(SignedJWT signedJWT) {
        return generateAuthRequest(signedJWT, new Scope(OIDCScopeValue.OPENID));
    }

    private AuthenticationRequest generateAuthRequest(SignedJWT signedJWT, Scope scope) {

        AuthenticationRequest.Builder builder =
                new AuthenticationRequest.Builder(
                                ResponseType.CODE, scope, CLIENT_ID, URI.create(REDIRECT_URI))
                        .state(STATE)
                        .nonce(new Nonce())
                        .requestObject(signedJWT);
        return builder.build();
    }
}
