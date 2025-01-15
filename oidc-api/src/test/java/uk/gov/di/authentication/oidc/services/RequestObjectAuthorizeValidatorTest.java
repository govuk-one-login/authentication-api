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
import com.nimbusds.openid.connect.sdk.OIDCClaimsRequest;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSetRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.oidc.validators.RequestObjectAuthorizeValidator;
import uk.gov.di.orchestration.shared.api.OidcAPI;
import uk.gov.di.orchestration.shared.entity.ClientRegistry;
import uk.gov.di.orchestration.shared.entity.ClientType;
import uk.gov.di.orchestration.shared.entity.CustomScopeValue;
import uk.gov.di.orchestration.shared.entity.LevelOfConfidence;
import uk.gov.di.orchestration.shared.entity.PublicKeySource;
import uk.gov.di.orchestration.shared.entity.ValidClaims;
import uk.gov.di.orchestration.shared.exceptions.ClientRedirectUriValidationException;
import uk.gov.di.orchestration.shared.exceptions.ClientSignatureValidationException;
import uk.gov.di.orchestration.shared.exceptions.JwksException;
import uk.gov.di.orchestration.shared.services.ClientSignatureValidationService;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.DynamoClientService;
import uk.gov.di.orchestration.sharedtest.helper.KeyPairHelper;

import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.oidc.helper.RequestObjectTestHelper.generateSignedJWT;
import static uk.gov.di.orchestration.sharedtest.helper.JsonArrayHelper.jsonArrayOf;

class RequestObjectAuthorizeValidatorTest {

    private static final String REDIRECT_URI = "https://localhost:8080";
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final DynamoClientService dynamoClientService = mock(DynamoClientService.class);
    private final IPVCapacityService ipvCapacityService = mock(IPVCapacityService.class);
    private final ClientSignatureValidationService clientSignatureValidationService =
            mock(ClientSignatureValidationService.class);
    private KeyPair keyPair;
    private static final String SCOPE = "openid doc-checking-app";
    private static final State STATE = new State();
    private static final Nonce NONCE = new Nonce();
    private static final ClientID CLIENT_ID = new ClientID("test-id");
    private static final URI OIDC_BASE_AUTHORIZE_URI = URI.create("https://localhost/authorize");
    private RequestObjectAuthorizeValidator service;
    private final OidcAPI oidcApi = mock(OidcAPI.class);

    @BeforeEach
    void setup() {
        when(oidcApi.authorizeURI()).thenReturn(OIDC_BASE_AUTHORIZE_URI);
        keyPair = KeyPairHelper.GENERATE_RSA_KEY_PAIR();
        service =
                new RequestObjectAuthorizeValidator(
                        configurationService,
                        dynamoClientService,
                        ipvCapacityService,
                        oidcApi,
                        clientSignatureValidationService);
        var clientRegistry =
                generateClientRegistry(
                        ClientType.APP.getValue(),
                        new Scope(
                                OIDCScopeValue.OPENID.getValue(),
                                CustomScopeValue.DOC_CHECKING_APP.getValue()));
        when(dynamoClientService.getClient(CLIENT_ID.getValue()))
                .thenReturn(Optional.of(clientRegistry));
        when(configurationService.getEnvironment()).thenReturn("test");
    }

    @Test
    void shouldSuccessfullyProcessRequestUriPayload()
            throws JOSEException, JwksException, ClientSignatureValidationException {
        List<String> scopes = new ArrayList<>();
        scopes.add("openid");
        scopes.add("doc-checking-app");
        var scope = Scope.parse(scopes);
        var jwtClaimsSet =
                new JWTClaimsSet.Builder()
                        .audience(OIDC_BASE_AUTHORIZE_URI.toString())
                        .claim("redirect_uri", REDIRECT_URI)
                        .claim("response_type", ResponseType.CODE.toString())
                        .claim("scope", scope.toString())
                        .claim("nonce", NONCE.getValue())
                        .claim("state", STATE.toString())
                        .claim("client_id", CLIENT_ID.getValue())
                        .claim("max_age", "1800")
                        .issuer(CLIENT_ID.getValue())
                        .build();
        var signedJWT = generateSignedJWT(jwtClaimsSet, keyPair);

        var requestObjectError = service.validate(generateAuthRequest(signedJWT));

        assertThat(requestObjectError, equalTo(Optional.empty()));
    }

    @Test
    void shouldSuccessfullyProcessRequestUriPayloadWhenVtrIsPresent()
            throws JOSEException, JwksException, ClientSignatureValidationException {
        when(ipvCapacityService.isIPVCapacityAvailable()).thenReturn(true);
        List<String> scopes = new ArrayList<>();
        scopes.add("openid");
        scopes.add("doc-checking-app");
        var scope = Scope.parse(scopes);
        var jwtClaimsSet =
                new JWTClaimsSet.Builder()
                        .audience(OIDC_BASE_AUTHORIZE_URI.toString())
                        .claim("redirect_uri", REDIRECT_URI)
                        .claim("response_type", ResponseType.CODE.toString())
                        .claim("scope", scope.toString())
                        .claim("nonce", NONCE.getValue())
                        .claim("state", STATE.toString())
                        .claim("client_id", CLIENT_ID.getValue())
                        .claim("vtr", List.of("P2.Cl.Cm"))
                        .issuer(CLIENT_ID.getValue())
                        .build();
        var signedJWT = generateSignedJWT(jwtClaimsSet, keyPair);

        var requestObjectError = service.validate(generateAuthRequest(signedJWT));

        assertThat(requestObjectError, equalTo(Optional.empty()));
    }

    @Test
    void shouldSuccessfullyProcessRequestObjectWithNumericalMaxAge()
            throws JOSEException, JwksException, ClientSignatureValidationException {
        List<String> scopes = new ArrayList<>();
        scopes.add("openid");
        scopes.add("doc-checking-app");
        var scope = Scope.parse(scopes);
        var jwtClaimsSet =
                new JWTClaimsSet.Builder()
                        .audience(OIDC_BASE_AUTHORIZE_URI.toString())
                        .claim("redirect_uri", REDIRECT_URI)
                        .claim("response_type", ResponseType.CODE.toString())
                        .claim("scope", scope.toString())
                        .claim("nonce", NONCE.getValue())
                        .claim("state", STATE.toString())
                        .claim("client_id", CLIENT_ID.getValue())
                        .claim("max_age", 1800)
                        .issuer(CLIENT_ID.getValue())
                        .build();
        var signedJWT = generateSignedJWT(jwtClaimsSet, keyPair);

        var requestObjectError = service.validate(generateAuthRequest(signedJWT));

        assertThat(requestObjectError, equalTo(Optional.empty()));
    }

    @Test
    void shouldThrowWhenRedirectUriIsInvalid() throws JOSEException {
        var jwtClaimsSet =
                new JWTClaimsSet.Builder()
                        .audience(OIDC_BASE_AUTHORIZE_URI.toString())
                        .claim("redirect_uri", "https://invalid-redirect-uri")
                        .claim("response_type", ResponseType.CODE.toString())
                        .claim("scope", SCOPE)
                        .claim("nonce", NONCE.getValue())
                        .claim("state", STATE.toString())
                        .claim("client_id", CLIENT_ID.getValue())
                        .issuer(CLIENT_ID.getValue())
                        .build();
        var authRequest = generateAuthRequest(generateSignedJWT(jwtClaimsSet, keyPair));
        assertThrows(
                ClientRedirectUriValidationException.class,
                () -> service.validate(authRequest),
                "Expected to throw exception");
    }

    @Test
    void shouldThrowWhenRedirectUriIsAbsent() throws JOSEException {
        var jwtClaimsSet =
                new JWTClaimsSet.Builder()
                        .audience(OIDC_BASE_AUTHORIZE_URI.toString())
                        .claim("response_type", ResponseType.CODE.toString())
                        .claim("scope", SCOPE)
                        .claim("nonce", NONCE.getValue())
                        .claim("state", STATE.toString())
                        .claim("client_id", CLIENT_ID.getValue())
                        .issuer(CLIENT_ID.getValue())
                        .build();
        var authRequest = generateAuthRequest(generateSignedJWT(jwtClaimsSet, keyPair));
        assertThrows(
                ClientRedirectUriValidationException.class,
                () -> service.validate(authRequest),
                "Expected to throw exception");
    }

    @Test
    void shouldThrowWhenInvalidClient() throws JOSEException {
        when(dynamoClientService.getClient(CLIENT_ID.getValue())).thenReturn(Optional.empty());
        var jwtClaimsSet =
                new JWTClaimsSet.Builder()
                        .audience(OIDC_BASE_AUTHORIZE_URI.toString())
                        .claim("redirect_uri", REDIRECT_URI)
                        .claim("response_type", ResponseType.CODE.toString())
                        .claim("scope", SCOPE)
                        .claim("nonce", NONCE.getValue())
                        .claim("state", STATE.toString())
                        .claim("client_id", CLIENT_ID.getValue())
                        .issuer(CLIENT_ID.getValue())
                        .build();
        var signedJWT = generateSignedJWT(jwtClaimsSet, keyPair);

        assertThrows(
                RuntimeException.class,
                () -> service.validate(generateAuthRequest(signedJWT)),
                "Expected to throw exception");
    }

    @Test
    void shouldReturnErrorWhenClientTypeIsNotAppOrWeb()
            throws JOSEException, JwksException, ClientSignatureValidationException {
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
                        .audience(OIDC_BASE_AUTHORIZE_URI.toString())
                        .claim("redirect_uri", REDIRECT_URI)
                        .claim("response_type", ResponseType.CODE.toString())
                        .claim("scope", SCOPE)
                        .claim("nonce", NONCE.getValue())
                        .claim("state", STATE.toString())
                        .claim("client_id", CLIENT_ID.getValue())
                        .issuer(CLIENT_ID.getValue())
                        .build();
        var signedJWT = generateSignedJWT(jwtClaimsSet, keyPair);

        var requestObjectError = service.validate(generateAuthRequest(signedJWT));

        assertTrue(requestObjectError.isPresent());
        assertThat(
                requestObjectError.get().errorObject(), equalTo(OAuth2Error.UNAUTHORIZED_CLIENT));
        assertThat(requestObjectError.get().redirectURI().toString(), equalTo(REDIRECT_URI));
        assertEquals(STATE, requestObjectError.get().state());
    }

    @Test
    void shouldReturnErrorForInvalidResponseType()
            throws JOSEException, JwksException, ClientSignatureValidationException {
        var jwtClaimsSet =
                new JWTClaimsSet.Builder()
                        .audience(OIDC_BASE_AUTHORIZE_URI.toString())
                        .claim("redirect_uri", REDIRECT_URI)
                        .claim("response_type", ResponseType.CODE_IDTOKEN.toString())
                        .claim("scope", SCOPE)
                        .claim("nonce", NONCE.getValue())
                        .claim("state", STATE.toString())
                        .issuer(CLIENT_ID.getValue())
                        .claim("client_id", CLIENT_ID.getValue())
                        .build();
        var authRequest = generateAuthRequest(generateSignedJWT(jwtClaimsSet, keyPair));
        var requestObjectError = service.validate(authRequest);

        assertTrue(requestObjectError.isPresent());
        assertThat(
                requestObjectError.get().errorObject(),
                equalTo(OAuth2Error.UNSUPPORTED_RESPONSE_TYPE));
        assertThat(requestObjectError.get().redirectURI().toString(), equalTo(REDIRECT_URI));
        assertEquals(STATE, requestObjectError.get().state());
    }

    @Test
    void shouldReturnErrorForInvalidResponseTypeInQueryParams()
            throws JOSEException, JwksException, ClientSignatureValidationException {
        var jwtClaimsSet =
                new JWTClaimsSet.Builder()
                        .audience(OIDC_BASE_AUTHORIZE_URI.toString())
                        .claim("redirect_uri", REDIRECT_URI)
                        .claim("response_type", ResponseType.CODE.toString())
                        .claim("scope", SCOPE)
                        .claim("nonce", NONCE.getValue())
                        .claim("state", STATE.toString())
                        .issuer(CLIENT_ID.getValue())
                        .claim("client_id", CLIENT_ID.getValue())
                        .build();

        var authRequest =
                new AuthenticationRequest.Builder(
                                ResponseType.IDTOKEN,
                                new Scope(OIDCScopeValue.OPENID),
                                CLIENT_ID,
                                URI.create(REDIRECT_URI))
                        .state(STATE)
                        .nonce(new Nonce())
                        .requestObject(generateSignedJWT(jwtClaimsSet, keyPair))
                        .build();
        var requestObjectError = service.validate(authRequest);

        assertTrue(requestObjectError.isPresent());
        assertThat(
                requestObjectError.get().errorObject(),
                equalTo(OAuth2Error.UNSUPPORTED_RESPONSE_TYPE));
        assertThat(requestObjectError.get().redirectURI().toString(), equalTo(REDIRECT_URI));
        assertEquals(STATE, requestObjectError.get().state());
    }

    @Test
    void shouldReturnErrorWhenClientIDIsInvalid()
            throws JOSEException, JwksException, ClientSignatureValidationException {
        var jwtClaimsSet =
                new JWTClaimsSet.Builder()
                        .audience(OIDC_BASE_AUTHORIZE_URI.toString())
                        .claim("redirect_uri", REDIRECT_URI)
                        .claim("response_type", ResponseType.CODE.toString())
                        .claim("scope", SCOPE)
                        .claim("nonce", NONCE.getValue())
                        .claim("state", STATE.toString())
                        .issuer(CLIENT_ID.getValue())
                        .claim("client_id", "invalid-client-id")
                        .build();
        var authRequest = generateAuthRequest(generateSignedJWT(jwtClaimsSet, keyPair));
        var requestObjectError = service.validate(authRequest);

        assertTrue(requestObjectError.isPresent());
        assertThat(
                requestObjectError.get().errorObject(), equalTo(OAuth2Error.UNAUTHORIZED_CLIENT));
        assertThat(requestObjectError.get().redirectURI().toString(), equalTo(REDIRECT_URI));
        assertEquals(STATE, requestObjectError.get().state());
    }

    @Test
    void shouldReturnErrorForUnsupportedScope()
            throws JOSEException, JwksException, ClientSignatureValidationException {
        var jwtClaimsSet =
                new JWTClaimsSet.Builder()
                        .audience(OIDC_BASE_AUTHORIZE_URI.toString())
                        .claim("redirect_uri", REDIRECT_URI)
                        .claim("response_type", ResponseType.CODE.toString())
                        .claim("scope", "openid profile")
                        .claim("nonce", NONCE.getValue())
                        .claim("state", STATE.toString())
                        .claim("client_id", CLIENT_ID.getValue())
                        .issuer(CLIENT_ID.getValue())
                        .build();
        var authRequest = generateAuthRequest(generateSignedJWT(jwtClaimsSet, keyPair));
        var requestObjectError = service.validate(authRequest);

        assertTrue(requestObjectError.isPresent());
        assertThat(requestObjectError.get().errorObject(), equalTo(OAuth2Error.INVALID_SCOPE));
        assertThat(requestObjectError.get().redirectURI().toString(), equalTo(REDIRECT_URI));
        assertEquals(STATE, requestObjectError.get().state());
    }

    @Test
    void shouldReturnErrorIfVtrIsNotPermittedForGivenClient()
            throws JOSEException, JwksException, ClientSignatureValidationException {
        var jwtClaimsSet =
                new JWTClaimsSet.Builder()
                        .audience(OIDC_BASE_AUTHORIZE_URI.toString())
                        .claim("redirect_uri", REDIRECT_URI)
                        .claim("response_type", ResponseType.CODE.toString())
                        .claim("scope", "openid")
                        .claim("nonce", NONCE.getValue())
                        .claim("state", STATE.toString())
                        .claim("client_id", CLIENT_ID.getValue())
                        .claim("vtr", jsonArrayOf("Cl.Cm.PCL250"))
                        .issuer(CLIENT_ID.getValue())
                        .build();
        var authRequest = generateAuthRequest(generateSignedJWT(jwtClaimsSet, keyPair));
        var requestObjectError = service.validate(authRequest);

        assertTrue(requestObjectError.isPresent());
        assertThat(
                requestObjectError.get().errorObject().toJSONObject(),
                equalTo(
                        new ErrorObject(
                                        OAuth2Error.INVALID_REQUEST_CODE,
                                        "Request vtr is not permitted")
                                .toJSONObject()));
        assertThat(requestObjectError.get().redirectURI().toString(), equalTo(REDIRECT_URI));
    }

    @Test
    void shouldReturnErrorWhenClientHasNotRegisteredDocAppScope()
            throws JOSEException, JwksException, ClientSignatureValidationException {
        var clientRegistry =
                generateClientRegistry(
                        ClientType.APP.getValue(), new Scope(OIDCScopeValue.OPENID.getValue()));
        when(dynamoClientService.getClient(CLIENT_ID.getValue()))
                .thenReturn(Optional.of(clientRegistry));

        var jwtClaimsSet =
                new JWTClaimsSet.Builder()
                        .audience(OIDC_BASE_AUTHORIZE_URI.toString())
                        .claim("redirect_uri", REDIRECT_URI)
                        .claim("response_type", ResponseType.CODE.toString())
                        .claim("scope", SCOPE)
                        .claim("nonce", NONCE.getValue())
                        .claim("state", STATE.toString())
                        .claim("client_id", CLIENT_ID.getValue())
                        .issuer(CLIENT_ID.getValue())
                        .build();
        var signedJWT = generateSignedJWT(jwtClaimsSet, keyPair);

        var requestObjectError = service.validate(generateAuthRequest(signedJWT));

        assertTrue(requestObjectError.isPresent());
        assertThat(requestObjectError.get().errorObject(), equalTo(OAuth2Error.INVALID_SCOPE));
        assertThat(requestObjectError.get().redirectURI().toString(), equalTo(REDIRECT_URI));
        assertEquals(STATE, requestObjectError.get().state());
    }

    @Test
    void shouldReturnErrorWhenAuthRequestContainsInvalidScope()
            throws JOSEException, JwksException, ClientSignatureValidationException {
        var jwtClaimsSet =
                new JWTClaimsSet.Builder()
                        .audience(OIDC_BASE_AUTHORIZE_URI.toString())
                        .claim("redirect_uri", REDIRECT_URI)
                        .claim("response_type", ResponseType.CODE.toString())
                        .claim("scope", SCOPE)
                        .claim("nonce", NONCE.getValue())
                        .claim("state", STATE.getValue())
                        .claim("client_id", CLIENT_ID.getValue())
                        .issuer(CLIENT_ID.getValue())
                        .build();
        var signedJWT = generateSignedJWT(jwtClaimsSet, keyPair);

        var requestObjectError =
                service.validate(
                        generateAuthRequest(
                                signedJWT, new Scope(OIDCScopeValue.OPENID, OIDCScopeValue.EMAIL)));

        assertTrue(requestObjectError.isPresent());
        assertThat(requestObjectError.get().errorObject(), equalTo(OAuth2Error.INVALID_SCOPE));
        assertThat(requestObjectError.get().redirectURI().toString(), equalTo(REDIRECT_URI));
        assertEquals(STATE, requestObjectError.get().state());
    }

    @Test
    void shouldReturnErrorForUnregisteredScope()
            throws JOSEException, JwksException, ClientSignatureValidationException {
        var jwtClaimsSet =
                new JWTClaimsSet.Builder()
                        .audience(OIDC_BASE_AUTHORIZE_URI.toString())
                        .claim("redirect_uri", REDIRECT_URI)
                        .claim("response_type", ResponseType.CODE.toString())
                        .claim("scope", "openid email")
                        .claim("nonce", NONCE.getValue())
                        .claim("state", STATE.getValue())
                        .claim("client_id", CLIENT_ID.getValue())
                        .issuer(CLIENT_ID.getValue())
                        .build();
        var authRequest = generateAuthRequest(generateSignedJWT(jwtClaimsSet, keyPair));
        var requestObjectError = service.validate(authRequest);

        assertTrue(requestObjectError.isPresent());
        assertThat(requestObjectError.get().errorObject(), equalTo(OAuth2Error.INVALID_SCOPE));
        assertThat(requestObjectError.get().redirectURI().toString(), equalTo(REDIRECT_URI));
        assertEquals(STATE, requestObjectError.get().state());
    }

    @Test
    void shouldReturnErrorForInvalidAudience()
            throws JOSEException, JwksException, ClientSignatureValidationException {
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

        var authRequest = generateAuthRequest(generateSignedJWT(jwtClaimsSet, keyPair));
        var requestObjectError = service.validate(authRequest);

        assertTrue(requestObjectError.isPresent());
        assertThat(requestObjectError.get().errorObject(), equalTo(OAuth2Error.ACCESS_DENIED));
        assertThat(requestObjectError.get().redirectURI().toString(), equalTo(REDIRECT_URI));
        assertEquals(STATE, requestObjectError.get().state());
    }

    @Test
    void shouldReturnErrorForInvalidIssuer()
            throws JOSEException, JwksException, ClientSignatureValidationException {
        var jwtClaimsSet =
                new JWTClaimsSet.Builder()
                        .audience(OIDC_BASE_AUTHORIZE_URI.toString())
                        .claim("redirect_uri", REDIRECT_URI)
                        .claim("response_type", ResponseType.CODE.toString())
                        .claim("scope", "openid")
                        .claim("nonce", NONCE.getValue())
                        .claim("state", STATE.getValue())
                        .claim("client_id", CLIENT_ID.getValue())
                        .issuer("invalid-client")
                        .build();
        var authRequest = generateAuthRequest(generateSignedJWT(jwtClaimsSet, keyPair));
        var requestObjectError = service.validate(authRequest);

        assertTrue(requestObjectError.isPresent());
        assertThat(
                requestObjectError.get().errorObject(), equalTo(OAuth2Error.UNAUTHORIZED_CLIENT));
        assertThat(requestObjectError.get().redirectURI().toString(), equalTo(REDIRECT_URI));
        assertEquals(STATE, requestObjectError.get().state());
    }

    @Test
    void shouldReturnErrorIfRequestClaimIsPresentJwt()
            throws JOSEException, JwksException, ClientSignatureValidationException {
        var jwtClaimsSet =
                new JWTClaimsSet.Builder()
                        .audience(OIDC_BASE_AUTHORIZE_URI.toString())
                        .claim("redirect_uri", REDIRECT_URI)
                        .claim("response_type", ResponseType.CODE.toString())
                        .claim("scope", "openid")
                        .claim("nonce", NONCE.getValue())
                        .claim("state", STATE.getValue())
                        .claim("client_id", CLIENT_ID.getValue())
                        .claim("request", "some-random-request-value")
                        .issuer(CLIENT_ID.getValue())
                        .build();
        generateSignedJWT(jwtClaimsSet, keyPair);
        var authRequest = generateAuthRequest(generateSignedJWT(jwtClaimsSet, keyPair));
        var requestObjectError = service.validate(authRequest);

        assertTrue(requestObjectError.isPresent());
        assertThat(requestObjectError.get().errorObject(), equalTo(OAuth2Error.INVALID_REQUEST));
        assertThat(requestObjectError.get().redirectURI().toString(), equalTo(REDIRECT_URI));
        assertEquals(STATE, requestObjectError.get().state());
    }

    @Test
    void shouldReturnErrorIfRequestUriClaimIsPresentJwt()
            throws JOSEException, JwksException, ClientSignatureValidationException {
        var jwtClaimsSet =
                new JWTClaimsSet.Builder()
                        .audience(OIDC_BASE_AUTHORIZE_URI.toString())
                        .claim("redirect_uri", REDIRECT_URI)
                        .claim("response_type", ResponseType.CODE.toString())
                        .claim("scope", "openid")
                        .claim("nonce", NONCE.getValue())
                        .claim("state", STATE.getValue())
                        .claim("client_id", CLIENT_ID.getValue())
                        .claim("request_uri", URI.create("https://localhost/request_uri"))
                        .issuer(CLIENT_ID.getValue())
                        .build();
        var authRequest = generateAuthRequest(generateSignedJWT(jwtClaimsSet, keyPair));
        var requestObjectError = service.validate(authRequest);

        assertTrue(requestObjectError.isPresent());
        assertThat(requestObjectError.get().errorObject(), equalTo(OAuth2Error.INVALID_REQUEST));
        assertThat(requestObjectError.get().redirectURI().toString(), equalTo(REDIRECT_URI));
        assertEquals(STATE, requestObjectError.get().state());
    }

    @Test
    void shouldThrowWhenUnableToValidateRequestJwtSignature()
            throws JOSEException,
                    NoSuchAlgorithmException,
                    ClientSignatureValidationException,
                    JwksException {
        var keyPair2 = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        var jwtClaimsSet =
                new JWTClaimsSet.Builder()
                        .audience(OIDC_BASE_AUTHORIZE_URI.toString())
                        .claim("redirect_uri", REDIRECT_URI)
                        .claim("response_type", ResponseType.CODE.toString())
                        .claim("scope", SCOPE)
                        .claim("nonce", NONCE.getValue())
                        .claim("state", STATE.getValue())
                        .claim("client_id", CLIENT_ID.getValue())
                        .issuer(CLIENT_ID.getValue())
                        .build();
        var authRequest = generateAuthRequest(generateSignedJWT(jwtClaimsSet, keyPair2));
        doThrow(new RuntimeException())
                .when(clientSignatureValidationService)
                .validate(any(SignedJWT.class), any(ClientRegistry.class));
        assertThrows(
                RuntimeException.class,
                () -> service.validate(authRequest),
                "Expected to throw exception");
    }

    @Test
    void shouldReturnErrorIfStateIsMissingFromRequestObject()
            throws JOSEException, JwksException, ClientSignatureValidationException {
        var jwtClaimsSet =
                new JWTClaimsSet.Builder()
                        .audience(OIDC_BASE_AUTHORIZE_URI.toString())
                        .claim("redirect_uri", REDIRECT_URI)
                        .claim("response_type", ResponseType.CODE.toString())
                        .claim("scope", SCOPE)
                        .claim("nonce", NONCE.getValue())
                        .claim("client_id", CLIENT_ID.getValue())
                        .issuer(CLIENT_ID.getValue())
                        .build();
        var signedJWT = generateSignedJWT(jwtClaimsSet, keyPair);

        var requestObjectError = service.validate(generateAuthRequest(signedJWT));

        assertTrue(requestObjectError.isPresent());
        assertThat(requestObjectError.get().errorObject(), equalTo(OAuth2Error.INVALID_REQUEST));
        assertThat(
                requestObjectError.get().errorObject().getDescription(),
                equalTo("Request is missing state parameter"));
        assertThat(requestObjectError.get().redirectURI().toString(), equalTo(REDIRECT_URI));
        assertNull(requestObjectError.get().state());
    }

    @Test
    void shouldSuccessfullyProcessRequestWhenNonceNotExpectedAndMissing()
            throws JOSEException, JwksException, ClientSignatureValidationException {
        when(ipvCapacityService.isIPVCapacityAvailable()).thenReturn(true);
        var clientRegistry =
                generateClientRegistry(
                        ClientType.APP.getValue(),
                        new Scope(
                                OIDCScopeValue.OPENID.getValue(),
                                CustomScopeValue.DOC_CHECKING_APP.getValue()));

        clientRegistry.withPermitMissingNonce(true);
        when(dynamoClientService.getClient(CLIENT_ID.getValue()))
                .thenReturn(Optional.of(clientRegistry));

        List<String> scopes = new ArrayList<>();
        scopes.add("openid");
        scopes.add("doc-checking-app");
        var scope = Scope.parse(scopes);
        var jwtClaimsSet =
                new JWTClaimsSet.Builder()
                        .audience(OIDC_BASE_AUTHORIZE_URI.toString())
                        .claim("redirect_uri", REDIRECT_URI)
                        .claim("response_type", ResponseType.CODE.toString())
                        .claim("scope", scope.toString())
                        .claim("state", STATE.toString())
                        .claim("client_id", CLIENT_ID.getValue())
                        .claim("vtr", List.of("P2.Cl.Cm"))
                        .issuer(CLIENT_ID.getValue())
                        .build();
        var signedJWT = generateSignedJWT(jwtClaimsSet, keyPair);

        AuthenticationRequest authenticationRequest =
                new AuthenticationRequest.Builder(
                                ResponseType.CODE, scope, CLIENT_ID, URI.create(REDIRECT_URI))
                        .state(STATE)
                        .requestObject(signedJWT)
                        .build();

        var requestObjectError = service.validate(authenticationRequest);

        assertThat(requestObjectError, equalTo(Optional.empty()));
    }

    @Test
    void shouldReturnErrorIfNonceIsExpectedAndMissingFromRequestObject()
            throws JOSEException, JwksException, ClientSignatureValidationException {
        var jwtClaimsSet =
                new JWTClaimsSet.Builder()
                        .audience(OIDC_BASE_AUTHORIZE_URI.toString())
                        .claim("redirect_uri", REDIRECT_URI)
                        .claim("response_type", ResponseType.CODE.toString())
                        .claim("scope", SCOPE)
                        .claim("state", STATE.getValue())
                        .claim("client_id", CLIENT_ID.getValue())
                        .issuer(CLIENT_ID.getValue())
                        .build();
        var signedJWT = generateSignedJWT(jwtClaimsSet, keyPair);

        var requestObjectError = service.validate(generateAuthRequest(signedJWT));

        assertTrue(requestObjectError.isPresent());
        assertThat(requestObjectError.get().errorObject(), equalTo(OAuth2Error.INVALID_REQUEST));
        assertThat(
                requestObjectError.get().errorObject().getDescription(),
                equalTo("Request is missing nonce parameter"));
        assertThat(requestObjectError.get().redirectURI().toString(), equalTo(REDIRECT_URI));
        assertEquals(STATE, requestObjectError.get().state());
    }

    @Test
    void shouldReturnErrorForInvalidUILocales()
            throws JOSEException, JwksException, ClientSignatureValidationException {
        var jwtClaimsSet =
                new JWTClaimsSet.Builder()
                        .audience(OIDC_BASE_AUTHORIZE_URI.toString())
                        .claim("redirect_uri", REDIRECT_URI)
                        .claim("response_type", ResponseType.CODE.toString())
                        .claim("scope", SCOPE)
                        .claim("nonce", NONCE.getValue())
                        .claim("state", STATE.toString())
                        .issuer(CLIENT_ID.getValue())
                        .claim("client_id", CLIENT_ID.getValue())
                        .claim("ui_locales", "123456")
                        .build();
        var authRequest = generateAuthRequest(generateSignedJWT(jwtClaimsSet, keyPair));
        var requestObjectError = service.validate(authRequest);

        assertTrue(requestObjectError.isPresent());
        assertThat(requestObjectError.get().errorObject(), equalTo(OAuth2Error.INVALID_REQUEST));
        assertThat(requestObjectError.get().redirectURI().toString(), equalTo(REDIRECT_URI));
        assertEquals(STATE, requestObjectError.get().state());
    }

    @Test
    void shouldReturnErrorForNegativeMaxAgeString()
            throws JOSEException, JwksException, ClientSignatureValidationException {
        var jwtClaimsSet =
                new JWTClaimsSet.Builder()
                        .audience(OIDC_BASE_AUTHORIZE_URI.toString())
                        .claim("redirect_uri", REDIRECT_URI)
                        .claim("response_type", ResponseType.CODE.toString())
                        .claim("scope", SCOPE)
                        .claim("nonce", NONCE.getValue())
                        .claim("state", STATE.toString())
                        .issuer(CLIENT_ID.getValue())
                        .claim("client_id", CLIENT_ID.getValue())
                        .claim("max_age", "-5")
                        .build();
        var authRequest = generateAuthRequest(generateSignedJWT(jwtClaimsSet, keyPair));
        var requestObjectError = service.validate(authRequest);

        assertTrue(requestObjectError.isPresent());
        assertThat(requestObjectError.get().errorObject(), equalTo(OAuth2Error.INVALID_REQUEST));
        assertThat(requestObjectError.get().redirectURI().toString(), equalTo(REDIRECT_URI));
        assertEquals(STATE, requestObjectError.get().state());
    }

    @Test
    void shouldReturnErrorForInvalidMaxAgeString()
            throws JOSEException, JwksException, ClientSignatureValidationException {
        var jwtClaimsSet =
                new JWTClaimsSet.Builder()
                        .audience(OIDC_BASE_AUTHORIZE_URI.toString())
                        .claim("redirect_uri", REDIRECT_URI)
                        .claim("response_type", ResponseType.CODE.toString())
                        .claim("scope", SCOPE)
                        .claim("nonce", NONCE.getValue())
                        .claim("state", STATE.toString())
                        .issuer(CLIENT_ID.getValue())
                        .claim("client_id", CLIENT_ID.getValue())
                        .claim("max_age", "NotANumber")
                        .build();
        var authRequest = generateAuthRequest(generateSignedJWT(jwtClaimsSet, keyPair));
        var requestObjectError = service.validate(authRequest);

        assertTrue(requestObjectError.isPresent());
        assertThat(requestObjectError.get().errorObject(), equalTo(OAuth2Error.INVALID_REQUEST));
        assertThat(requestObjectError.get().redirectURI().toString(), equalTo(REDIRECT_URI));
        assertEquals(STATE, requestObjectError.get().state());
    }

    @Test
    void shouldReturnErrorForNegativedMaxAgeInteger()
            throws JOSEException, JwksException, ClientSignatureValidationException {
        var jwtClaimsSet =
                new JWTClaimsSet.Builder()
                        .audience(OIDC_BASE_AUTHORIZE_URI.toString())
                        .claim("redirect_uri", REDIRECT_URI)
                        .claim("response_type", ResponseType.CODE.toString())
                        .claim("scope", SCOPE)
                        .claim("nonce", NONCE.getValue())
                        .claim("state", STATE.toString())
                        .issuer(CLIENT_ID.getValue())
                        .claim("client_id", CLIENT_ID.getValue())
                        .claim("max_age", -5)
                        .build();
        var authRequest = generateAuthRequest(generateSignedJWT(jwtClaimsSet, keyPair));
        var requestObjectError = service.validate(authRequest);

        assertTrue(requestObjectError.isPresent());
        assertThat(requestObjectError.get().errorObject(), equalTo(OAuth2Error.INVALID_REQUEST));
        assertThat(requestObjectError.get().redirectURI().toString(), equalTo(REDIRECT_URI));
        assertEquals(STATE, requestObjectError.get().state());
    }

    @Test
    void shouldReturnErrorForAnUnknownClaimsJsonString()
            throws JOSEException, JwksException, ClientSignatureValidationException {
        var claimSet =
                new OIDCClaimsRequest()
                        .withUserInfoClaimsRequest(
                                new ClaimsSetRequest()
                                        .add(
                                                new ClaimsSetRequest.Entry(
                                                        ValidClaims.CORE_IDENTITY_JWT.getValue()))
                                        .add("https://vocab.example.com/v2/example-claim"));
        var jwtClaimsSet =
                new JWTClaimsSet.Builder()
                        .audience(OIDC_BASE_AUTHORIZE_URI.toString())
                        .claim("redirect_uri", REDIRECT_URI)
                        .claim("response_type", ResponseType.CODE.toString())
                        .claim("scope", SCOPE)
                        .claim("nonce", NONCE.getValue())
                        .claim("state", STATE.toString())
                        .issuer(CLIENT_ID.getValue())
                        .claim("client_id", CLIENT_ID.getValue())
                        .claim("claims", claimSet.toJSONString())
                        .build();
        var authRequest = generateAuthRequest(generateSignedJWT(jwtClaimsSet, keyPair));
        var requestObjectError = service.validate(authRequest);

        assertTrue(requestObjectError.isPresent());
        assertThat(requestObjectError.get().errorObject(), equalTo(OAuth2Error.INVALID_REQUEST));
        assertThat(requestObjectError.get().redirectURI().toString(), equalTo(REDIRECT_URI));
        assertEquals(STATE, requestObjectError.get().state());
    }

    @Test
    void shouldReturnErrorForAnClaimsNotSupportedByClientJsonString()
            throws JOSEException, JwksException, ClientSignatureValidationException {
        var claimSet =
                new OIDCClaimsRequest()
                        .withUserInfoClaimsRequest(
                                new ClaimsSetRequest()
                                        .add(
                                                new ClaimsSetRequest.Entry(
                                                        ValidClaims.CORE_IDENTITY_JWT.getValue()))
                                        .add(ValidClaims.INHERITED_IDENTITY_JWT.getValue()));
        var jwtClaimsSet =
                new JWTClaimsSet.Builder()
                        .audience(OIDC_BASE_AUTHORIZE_URI.toString())
                        .claim("redirect_uri", REDIRECT_URI)
                        .claim("response_type", ResponseType.CODE.toString())
                        .claim("scope", SCOPE)
                        .claim("nonce", NONCE.getValue())
                        .claim("state", STATE.toString())
                        .issuer(CLIENT_ID.getValue())
                        .claim("client_id", CLIENT_ID.getValue())
                        .claim("claims", claimSet.toJSONString())
                        .build();
        var authRequest = generateAuthRequest(generateSignedJWT(jwtClaimsSet, keyPair));
        var requestObjectError = service.validate(authRequest);

        assertTrue(requestObjectError.isPresent());
        assertThat(requestObjectError.get().errorObject(), equalTo(OAuth2Error.INVALID_REQUEST));
        assertThat(requestObjectError.get().redirectURI().toString(), equalTo(REDIRECT_URI));
        assertEquals(STATE, requestObjectError.get().state());
    }

    @Test
    void shouldReturnErrorForAnUnknownClaimsJsonObject()
            throws JOSEException, JwksException, ClientSignatureValidationException {
        var claimSet =
                new OIDCClaimsRequest()
                        .withUserInfoClaimsRequest(
                                new ClaimsSetRequest()
                                        .add(
                                                new ClaimsSetRequest.Entry(
                                                        ValidClaims.CORE_IDENTITY_JWT.getValue()))
                                        .add("https://vocab.example.com/v2/example-claim"));
        var jwtClaimsSet =
                new JWTClaimsSet.Builder()
                        .audience(OIDC_BASE_AUTHORIZE_URI.toString())
                        .claim("redirect_uri", REDIRECT_URI)
                        .claim("response_type", ResponseType.CODE.toString())
                        .claim("scope", SCOPE)
                        .claim("nonce", NONCE.getValue())
                        .claim("state", STATE.toString())
                        .issuer(CLIENT_ID.getValue())
                        .claim("client_id", CLIENT_ID.getValue())
                        .claim("claims", claimSet.toJSONObject())
                        .build();
        var authRequest = generateAuthRequest(generateSignedJWT(jwtClaimsSet, keyPair));
        var requestObjectError = service.validate(authRequest);

        assertTrue(requestObjectError.isPresent());
        assertThat(requestObjectError.get().errorObject(), equalTo(OAuth2Error.INVALID_REQUEST));
        assertThat(requestObjectError.get().redirectURI().toString(), equalTo(REDIRECT_URI));
        assertEquals(STATE, requestObjectError.get().state());
    }

    @Test
    void shouldReturnErrorForAnClaimsNotSupportedByClientJsonObject()
            throws JOSEException, JwksException, ClientSignatureValidationException {
        var claimSet =
                new OIDCClaimsRequest()
                        .withUserInfoClaimsRequest(
                                new ClaimsSetRequest()
                                        .add(
                                                new ClaimsSetRequest.Entry(
                                                        ValidClaims.CORE_IDENTITY_JWT.getValue()))
                                        .add(ValidClaims.INHERITED_IDENTITY_JWT.getValue()));
        var jwtClaimsSet =
                new JWTClaimsSet.Builder()
                        .audience(OIDC_BASE_AUTHORIZE_URI.toString())
                        .claim("redirect_uri", REDIRECT_URI)
                        .claim("response_type", ResponseType.CODE.toString())
                        .claim("scope", SCOPE)
                        .claim("nonce", NONCE.getValue())
                        .claim("state", STATE.toString())
                        .issuer(CLIENT_ID.getValue())
                        .claim("client_id", CLIENT_ID.getValue())
                        .claim("claims", claimSet.toJSONObject())
                        .build();
        var authRequest = generateAuthRequest(generateSignedJWT(jwtClaimsSet, keyPair));
        var requestObjectError = service.validate(authRequest);

        assertTrue(requestObjectError.isPresent());
        assertThat(requestObjectError.get().errorObject(), equalTo(OAuth2Error.INVALID_REQUEST));
        assertThat(requestObjectError.get().redirectURI().toString(), equalTo(REDIRECT_URI));
        assertEquals(STATE, requestObjectError.get().state());
    }

    private ClientRegistry generateClientRegistry(String clientType, Scope scope) {
        return new ClientRegistry()
                .withClientID(CLIENT_ID.getValue())
                .withPublicKeySource(PublicKeySource.STATIC.getValue())
                .withPublicKey(
                        Base64.getMimeEncoder().encodeToString(keyPair.getPublic().getEncoded()))
                .withClientName("test-client")
                .withScopes(scope.toStringList())
                .withRedirectUrls(singletonList(REDIRECT_URI))
                .withSectorIdentifierUri("https://test.com")
                .withSubjectType("pairwise")
                .withClientLoCs(singletonList(LevelOfConfidence.MEDIUM_LEVEL.getValue()))
                .withClientType(clientType)
                .withClaims(
                        List.of(
                                ValidClaims.ADDRESS.getValue(),
                                ValidClaims.CORE_IDENTITY_JWT.getValue(),
                                ValidClaims.PASSPORT.getValue(),
                                ValidClaims.RETURN_CODE.getValue()));
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
