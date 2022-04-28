package uk.gov.di.authentication.oidc.services;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
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
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.ClientType;
import uk.gov.di.authentication.shared.entity.CustomScopeValue;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoClientService;
import uk.gov.di.authentication.sharedtest.helper.KeyPairHelper;

import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Optional;

import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class RequestObjectServiceTest {

    private static final String REDIRECT_URI = "https://localhost:8080";
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final DynamoClientService dynamoClientService = mock(DynamoClientService.class);
    private KeyPair keyPair;
    private static final String SCOPE = "openid doc-checking-app";
    private static final State STATE = new State();
    private static final ClientID CLIENT_ID = new ClientID("test-id");
    private static final String OIDC_BASE_URI = "https://localhost";
    private static final String AUDIENCE = "https://localhost/authorize";
    private RequestObjectService service;

    @BeforeEach
    void setup() {
        when(configurationService.getOidcApiBaseURL()).thenReturn(Optional.of(OIDC_BASE_URI));
        keyPair = KeyPairHelper.GENERATE_RSA_KEY_PAIR();
        service = new RequestObjectService(dynamoClientService, configurationService);
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
    void shouldSuccessfullyProcessRequestUriPayload() throws JOSEException {
        var jwtClaimsSet =
                new JWTClaimsSet.Builder()
                        .audience(AUDIENCE)
                        .claim("redirect_uri", REDIRECT_URI)
                        .claim("response_type", ResponseType.CODE.toString())
                        .claim("scope", SCOPE)
                        .claim("state", new State())
                        .claim("client_id", CLIENT_ID.getValue())
                        .issuer(CLIENT_ID.getValue())
                        .build();
        var signedJWT = generateSignedJWT(jwtClaimsSet);

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
                        .claim("client_id", CLIENT_ID.getValue())
                        .issuer(CLIENT_ID.getValue())
                        .build();
        var authRequest = generateAuthRequest(generateSignedJWT(jwtClaimsSet));
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
                        .claim("client_id", CLIENT_ID.getValue())
                        .issuer(CLIENT_ID.getValue())
                        .build();
        var signedJWT = generateSignedJWT(jwtClaimsSet);

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
                        .claim("state", new State())
                        .claim("client_id", CLIENT_ID.getValue())
                        .issuer(CLIENT_ID.getValue())
                        .build();
        var signedJWT = generateSignedJWT(jwtClaimsSet);

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
                        .issuer(CLIENT_ID.getValue())
                        .claim("client_id", CLIENT_ID.getValue())
                        .build();
        var authRequest = generateAuthRequest(generateSignedJWT(jwtClaimsSet));
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
                        .issuer(CLIENT_ID.getValue())
                        .claim("client_id", "invalid-client-id")
                        .build();
        var authRequest = generateAuthRequest(generateSignedJWT(jwtClaimsSet));
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
                        .claim("client_id", CLIENT_ID.getValue())
                        .issuer(CLIENT_ID.getValue())
                        .build();
        var authRequest = generateAuthRequest(generateSignedJWT(jwtClaimsSet));
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
                        .claim("client_id", CLIENT_ID.getValue())
                        .issuer(CLIENT_ID.getValue())
                        .build();
        var authRequest = generateAuthRequest(generateSignedJWT(jwtClaimsSet));
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
                        .claim("state", new State())
                        .claim("client_id", CLIENT_ID.getValue())
                        .issuer(CLIENT_ID.getValue())
                        .build();
        var signedJWT = generateSignedJWT(jwtClaimsSet);

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
                        .claim("state", new State())
                        .claim("client_id", CLIENT_ID.getValue())
                        .issuer(CLIENT_ID.getValue())
                        .build();
        var signedJWT = generateSignedJWT(jwtClaimsSet);

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
                        .claim("client_id", CLIENT_ID.getValue())
                        .issuer(CLIENT_ID.getValue())
                        .build();
        var authRequest = generateAuthRequest(generateSignedJWT(jwtClaimsSet));
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
                        .claim("client_id", CLIENT_ID.getValue())
                        .issuer(CLIENT_ID.getValue())
                        .build();

        var authRequest = generateAuthRequest(generateSignedJWT(jwtClaimsSet));
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
                        .claim("client_id", CLIENT_ID.getValue())
                        .issuer("invalid-client")
                        .build();
        var authRequest = generateAuthRequest(generateSignedJWT(jwtClaimsSet));
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
                        .claim("client_id", CLIENT_ID.getValue())
                        .claim("request", "some-random-request-value")
                        .issuer(CLIENT_ID.getValue())
                        .build();
        generateSignedJWT(jwtClaimsSet);
        var authRequest = generateAuthRequest(generateSignedJWT(jwtClaimsSet));
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
                        .claim("client_id", CLIENT_ID.getValue())
                        .claim("request_uri", URI.create("https://localhost/request_uri"))
                        .issuer(CLIENT_ID.getValue())
                        .build();
        var authRequest = generateAuthRequest(generateSignedJWT(jwtClaimsSet));
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
                        .claim("client_id", CLIENT_ID.getValue())
                        .issuer(CLIENT_ID.getValue())
                        .build();
        var signedJWT = generateSignedJWT(jwtClaimsSet);

        var requestObjectError = service.validateRequestObject(generateAuthRequest(signedJWT));

        assertTrue(requestObjectError.isPresent());
        assertThat(requestObjectError.get().getErrorObject(), equalTo(OAuth2Error.INVALID_REQUEST));
        assertThat(
                requestObjectError.get().getErrorObject().getDescription(),
                equalTo("Request is missing state parameter"));
        assertThat(requestObjectError.get().getRedirectURI().toString(), equalTo(REDIRECT_URI));
    }

    private SignedJWT generateSignedJWT(JWTClaimsSet jwtClaimsSet) throws JOSEException {
        return generateSignedJWT(jwtClaimsSet, keyPair);
    }

    private SignedJWT generateSignedJWT(JWTClaimsSet jwtClaimsSet, KeyPair keyPair)
            throws JOSEException {
        var jwsHeader = new JWSHeader(JWSAlgorithm.RS256);
        var signedJWT = new SignedJWT(jwsHeader, jwtClaimsSet);
        var signer = new RSASSASigner(keyPair.getPrivate());
        signedJWT.sign(signer);
        return signedJWT;
    }

    private ClientRegistry generateClientRegistry(String clientType, Scope scope) {
        return new ClientRegistry()
                .setClientID(CLIENT_ID.getValue())
                .setPublicKey(
                        Base64.getMimeEncoder().encodeToString(keyPair.getPublic().getEncoded()))
                .setConsentRequired(false)
                .setClientName("test-client")
                .setScopes(scope.toStringList())
                .setRedirectUrls(singletonList(REDIRECT_URI))
                .setSectorIdentifierUri("https://test.com")
                .setSubjectType("pairwise")
                .setClientType(clientType);
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
