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
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCClaimsRequest;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSetRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import uk.gov.di.authentication.oidc.validators.RequestObjectAuthorizeValidator;
import uk.gov.di.orchestration.shared.api.OidcAPI;
import uk.gov.di.orchestration.shared.entity.Channel;
import uk.gov.di.orchestration.shared.entity.ClientRegistry;
import uk.gov.di.orchestration.shared.entity.ClientType;
import uk.gov.di.orchestration.shared.entity.CustomScopeValue;
import uk.gov.di.orchestration.shared.entity.LevelOfConfidence;
import uk.gov.di.orchestration.shared.entity.PublicKeySource;
import uk.gov.di.orchestration.shared.entity.ValidClaims;
import uk.gov.di.orchestration.shared.exceptions.ClientRedirectUriValidationException;
import uk.gov.di.orchestration.shared.exceptions.ClientSignatureValidationException;
import uk.gov.di.orchestration.shared.exceptions.InvalidResponseModeException;
import uk.gov.di.orchestration.shared.exceptions.JwksException;
import uk.gov.di.orchestration.shared.services.ClientSignatureValidationService;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.DynamoClientService;
import uk.gov.di.orchestration.sharedtest.helper.KeyPairHelper;

import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
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
    private static final String PKCE_CODE_CHALLENGE = "aCodeChallenge";
    private static final String VALID_LOGIN_HINT = "joe.bloggs@digital.cabinet-office.gov.uk";
    private static final String INVALID_LOGIN_HINT =
            "11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111@digital.cabinet-office.gov.uk";
    private RequestObjectAuthorizeValidator validator;
    private final OidcAPI oidcApi = mock(OidcAPI.class);

    @BeforeEach
    void setup() {
        when(oidcApi.authorizeURI()).thenReturn(OIDC_BASE_AUTHORIZE_URI);
        keyPair = KeyPairHelper.GENERATE_RSA_KEY_PAIR();
        validator =
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
        var jwtClaimsSet = getDefaultJWTClaimsSetBuilder().build();
        var signedJWT = generateSignedJWT(jwtClaimsSet, keyPair);

        var requestObjectError = validator.validate(generateAuthRequest(signedJWT));

        assertThat(requestObjectError, equalTo(Optional.empty()));
    }

    @Test
    void shouldSuccessfullyProcessRequestUriPayloadWhenVtrIsPresent()
            throws JOSEException, JwksException, ClientSignatureValidationException {
        when(ipvCapacityService.isIPVCapacityAvailable()).thenReturn(true);
        var jwtClaimsSet =
                getDefaultJWTClaimsSetBuilder().claim("vtr", List.of("P2.Cl.Cm")).build();
        var signedJWT = generateSignedJWT(jwtClaimsSet, keyPair);

        var requestObjectError = validator.validate(generateAuthRequest(signedJWT));

        assertThat(requestObjectError, equalTo(Optional.empty()));
    }

    @Test
    void shouldSuccessfullyProcessRequestObjectWithNumericalMaxAge()
            throws JOSEException, JwksException, ClientSignatureValidationException {
        var jwtClaimsSet = getDefaultJWTClaimsSetBuilder().claim("max_age", 1800).build();
        var signedJWT = generateSignedJWT(jwtClaimsSet, keyPair);

        var requestObjectError = validator.validate(generateAuthRequest(signedJWT));

        assertThat(requestObjectError, equalTo(Optional.empty()));
    }

    @Test
    void shouldThrowWhenRedirectUriIsInvalid() throws JOSEException {
        var jwtClaimsSet =
                getDefaultJWTClaimsSetBuilder()
                        .claim("redirect_uri", "https://invalid-redirect-uri")
                        .build();
        var authRequest = generateAuthRequest(generateSignedJWT(jwtClaimsSet, keyPair));
        assertThrows(
                ClientRedirectUriValidationException.class,
                () -> validator.validate(authRequest),
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
                () -> validator.validate(authRequest),
                "Expected to throw exception");
    }

    @Test
    void shouldThrowWhenInvalidClient() throws JOSEException {
        when(dynamoClientService.getClient(CLIENT_ID.getValue())).thenReturn(Optional.empty());
        var jwtClaimsSet = getDefaultJWTClaimsSetBuilder().build();
        var signedJWT = generateSignedJWT(jwtClaimsSet, keyPair);

        assertThrows(
                RuntimeException.class,
                () -> validator.validate(generateAuthRequest(signedJWT)),
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
        var jwtClaimsSet = getDefaultJWTClaimsSetBuilder().build();
        var signedJWT = generateSignedJWT(jwtClaimsSet, keyPair);

        var requestObjectError = validator.validate(generateAuthRequest(signedJWT));

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
                getDefaultJWTClaimsSetBuilder()
                        .claim("response_type", ResponseType.CODE_IDTOKEN.toString())
                        .build();
        var authRequest = generateAuthRequest(generateSignedJWT(jwtClaimsSet, keyPair));
        var requestObjectError = validator.validate(authRequest);

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
        var jwtClaimsSet = getDefaultJWTClaimsSetBuilder().build();
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
        var requestObjectError = validator.validate(authRequest);

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
                getDefaultJWTClaimsSetBuilder().claim("client_id", "invalid-client-id").build();
        var authRequest = generateAuthRequest(generateSignedJWT(jwtClaimsSet, keyPair));
        var requestObjectError = validator.validate(authRequest);

        assertTrue(requestObjectError.isPresent());
        assertThat(
                requestObjectError.get().errorObject(), equalTo(OAuth2Error.UNAUTHORIZED_CLIENT));
        assertThat(requestObjectError.get().redirectURI().toString(), equalTo(REDIRECT_URI));
        assertEquals(STATE, requestObjectError.get().state());
    }

    @Test
    void shouldReturnErrorForUnsupportedScope()
            throws JOSEException, JwksException, ClientSignatureValidationException {
        var jwtClaimsSet = getDefaultJWTClaimsSetBuilder().claim("scope", "openid profile").build();
        var authRequest = generateAuthRequest(generateSignedJWT(jwtClaimsSet, keyPair));
        var requestObjectError = validator.validate(authRequest);

        assertTrue(requestObjectError.isPresent());
        assertThat(requestObjectError.get().errorObject(), equalTo(OAuth2Error.INVALID_SCOPE));
        assertThat(requestObjectError.get().redirectURI().toString(), equalTo(REDIRECT_URI));
        assertEquals(STATE, requestObjectError.get().state());
    }

    @Test
    void shouldReturnErrorIfVtrIsNotPermittedForGivenClient()
            throws JOSEException, JwksException, ClientSignatureValidationException {
        var jwtClaimsSet =
                getDefaultJWTClaimsSetBuilder().claim("vtr", jsonArrayOf("Cl.Cm.PCL250")).build();
        var authRequest = generateAuthRequest(generateSignedJWT(jwtClaimsSet, keyPair));
        var requestObjectError = validator.validate(authRequest);

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
    void shouldThrowErrorForInvalidResponseMode() throws JOSEException {
        var jwtClaimsSet = getDefaultJWTClaimsSetBuilder().claim("response_mode", "code").build();
        var authRequest = generateAuthRequest(generateSignedJWT(jwtClaimsSet, keyPair));
        assertThrows(InvalidResponseModeException.class, () -> validator.validate(authRequest));
    }

    @Test
    void shouldThrowErrorForInvalidResponseModeBeforeValidatingARedirectingError()
            throws JOSEException {
        // No state is an error we redirect back to the  RP for
        var jwtClaimsSet =
                new JWTClaimsSet.Builder()
                        .audience(OIDC_BASE_AUTHORIZE_URI.toString())
                        .claim("redirect_uri", REDIRECT_URI)
                        .claim("response_type", ResponseType.CODE.toString())
                        .claim("scope", "openid")
                        .claim("nonce", NONCE.getValue())
                        .claim("client_id", CLIENT_ID.getValue())
                        .claim("response_mode", "code")
                        .issuer(CLIENT_ID.getValue())
                        .build();
        var authRequest = generateAuthRequest(generateSignedJWT(jwtClaimsSet, keyPair));
        assertThrows(InvalidResponseModeException.class, () -> validator.validate(authRequest));
    }

    @ParameterizedTest
    @ValueSource(strings = {"query", "fragment"})
    void shouldNotErrorIfResponseModeValid(String responseMode)
            throws JOSEException, JwksException, ClientSignatureValidationException {
        var jwtClaimsSet =
                getDefaultJWTClaimsSetBuilder().claim("response_mode", responseMode).build();
        var authRequest = generateAuthRequest(generateSignedJWT(jwtClaimsSet, keyPair));
        var requestObjectError = validator.validate(authRequest);

        assertTrue(requestObjectError.isEmpty());
    }

    @Test
    void shouldNotReturnErrorWhenPkceCodeChallengeAndMethodAreMissingAndPkceIsNotEnabled()
            throws JOSEException, JwksException, ClientSignatureValidationException {
        when(configurationService.isPkceEnabled()).thenReturn(false);

        var jwtClaimsSet = getDefaultJWTClaimsSetBuilder().claim("scope", "openid").build();
        var authRequest = generateAuthRequest(generateSignedJWT(jwtClaimsSet, keyPair));

        var requestObjectError = validator.validate(authRequest);

        assertTrue(requestObjectError.isEmpty());
    }

    @Test
    void shouldNotReturnErrorWhenPkceCodeChallengeAndMethodAreMissingAndPkceIsEnabled()
            throws JOSEException, JwksException, ClientSignatureValidationException {
        when(configurationService.isPkceEnabled()).thenReturn(true);

        var jwtClaimsSet = getDefaultJWTClaimsSetBuilder().claim("scope", "openid").build();
        var authRequest = generateAuthRequest(generateSignedJWT(jwtClaimsSet, keyPair));

        var requestObjectError = validator.validate(authRequest);

        assertTrue(requestObjectError.isEmpty());
    }

    @Test
    void shouldReturnErrorWhenPkceIsEnforcedAndCodeChallengeMissing()
            throws JOSEException, JwksException, ClientSignatureValidationException {
        var clientRegistry =
                generateClientRegistry(
                        ClientType.APP.getValue(), new Scope(OIDCScopeValue.OPENID.getValue()));
        clientRegistry.setPKCEEnforced(true);
        when(dynamoClientService.getClient(CLIENT_ID.getValue()))
                .thenReturn(Optional.of(clientRegistry));
        when(configurationService.isPkceEnabled()).thenReturn(true);

        var jwtClaimsSet = getDefaultJWTClaimsSetBuilder().claim("scope", "openid").build();
        var authRequest = generateAuthRequest(generateSignedJWT(jwtClaimsSet, keyPair));

        var requestObjectError = validator.validate(authRequest);

        assertTrue(requestObjectError.isPresent());
        assertThat(
                requestObjectError.get().errorObject().toJSONObject(),
                equalTo(
                        new ErrorObject(
                                        OAuth2Error.INVALID_REQUEST_CODE,
                                        "Request is missing code_challenge parameter, but PKCE is enforced.")
                                .toJSONObject()));
        assertThat(requestObjectError.get().redirectURI().toString(), equalTo(REDIRECT_URI));
        assertEquals(STATE, requestObjectError.get().state());
    }

    @Test
    void shouldReturnErrorWhenPkceCodeChallengeMethodIsExpectedAndIsMissing()
            throws JOSEException, JwksException, ClientSignatureValidationException {
        when(configurationService.isPkceEnabled()).thenReturn(true);

        var jwtClaimsSet =
                getDefaultJWTClaimsSetBuilder()
                        .claim("scope", "openid")
                        .claim("code_challenge", PKCE_CODE_CHALLENGE)
                        .build();
        var authRequest = generateAuthRequest(generateSignedJWT(jwtClaimsSet, keyPair));

        var requestObjectError = validator.validate(authRequest);

        assertTrue(requestObjectError.isPresent());
        assertThat(
                requestObjectError.get().errorObject().toJSONObject(),
                equalTo(
                        new ErrorObject(
                                        OAuth2Error.INVALID_REQUEST_CODE,
                                        "Request is missing code_challenge_method parameter. code_challenge_method is required when code_challenge is present.")
                                .toJSONObject()));
        assertThat(requestObjectError.get().redirectURI().toString(), equalTo(REDIRECT_URI));
        assertEquals(STATE, requestObjectError.get().state());
    }

    @Test
    void shouldReturnErrorWhenPkceCodeChallengeMethodIsExpectedAndIsInvalid()
            throws JOSEException, JwksException, ClientSignatureValidationException {
        when(configurationService.isPkceEnabled()).thenReturn(true);

        var invalidCodeChallengeMethod = CodeChallengeMethod.PLAIN.getValue();

        var jwtClaimsSet =
                getDefaultJWTClaimsSetBuilder()
                        .claim("scope", "openid")
                        .claim("code_challenge", PKCE_CODE_CHALLENGE)
                        .claim("code_challenge_method", invalidCodeChallengeMethod)
                        .issuer(CLIENT_ID.getValue())
                        .build();
        var authRequest = generateAuthRequest(generateSignedJWT(jwtClaimsSet, keyPair));

        var requestObjectError = validator.validate(authRequest);

        assertTrue(requestObjectError.isPresent());
        assertThat(
                requestObjectError.get().errorObject().toJSONObject(),
                equalTo(
                        new ErrorObject(
                                        OAuth2Error.INVALID_REQUEST_CODE,
                                        "Invalid value for code_challenge_method parameter.")
                                .toJSONObject()));
        assertThat(requestObjectError.get().redirectURI().toString(), equalTo(REDIRECT_URI));
        assertEquals(STATE, requestObjectError.get().state());
    }

    @Test
    void shouldNotReturnErrorWhenPkceCodeChallengeAndMethodAreValid()
            throws JOSEException, JwksException, ClientSignatureValidationException {
        when(configurationService.isPkceEnabled()).thenReturn(true);

        var codeChallengeMethod = CodeChallengeMethod.S256.getValue();

        var jwtClaimsSet =
                getDefaultJWTClaimsSetBuilder()
                        .claim("scope", "openid")
                        .claim("code_challenge", PKCE_CODE_CHALLENGE)
                        .claim("code_challenge_method", codeChallengeMethod)
                        .build();
        var authRequest = generateAuthRequest(generateSignedJWT(jwtClaimsSet, keyPair));

        var requestObjectError = validator.validate(authRequest);

        assertTrue(requestObjectError.isEmpty());
    }

    @Test
    void shouldNotReturnErrorWhenLoginHintIsValid()
            throws JOSEException, JwksException, ClientSignatureValidationException {
        var jwtClaimsSet =
                getDefaultJWTClaimsSetBuilder().claim("login_hint", VALID_LOGIN_HINT).build();
        var authRequest = generateAuthRequest(generateSignedJWT(jwtClaimsSet, keyPair));

        var requestObjectError = validator.validate(authRequest);

        assertTrue(requestObjectError.isEmpty());
    }

    @Test
    void shouldErrorWhenLoginHintIsInvalid()
            throws JOSEException, JwksException, ClientSignatureValidationException {
        var jwtClaimsSet =
                getDefaultJWTClaimsSetBuilder().claim("login_hint", INVALID_LOGIN_HINT).build();
        var authRequest = generateAuthRequest(generateSignedJWT(jwtClaimsSet, keyPair));

        var requestObjectError = validator.validate(authRequest);

        assertTrue(requestObjectError.isPresent());
        assertThat(
                requestObjectError.get().errorObject().toJSONObject(),
                equalTo(
                        new ErrorObject(
                                        OAuth2Error.INVALID_REQUEST_CODE,
                                        "login_hint parameter is invalid")
                                .toJSONObject()));
        assertThat(requestObjectError.get().redirectURI().toString(), equalTo(REDIRECT_URI));
        assertEquals(STATE, requestObjectError.get().state());
    }

    @Test
    void shouldReturnErrorWhenClientHasNotRegisteredDocAppScope()
            throws JOSEException, JwksException, ClientSignatureValidationException {
        var clientRegistry =
                generateClientRegistry(
                        ClientType.APP.getValue(), new Scope(OIDCScopeValue.OPENID.getValue()));
        when(dynamoClientService.getClient(CLIENT_ID.getValue()))
                .thenReturn(Optional.of(clientRegistry));

        var jwtClaimsSet = getDefaultJWTClaimsSetBuilder().build();
        var signedJWT = generateSignedJWT(jwtClaimsSet, keyPair);

        var requestObjectError = validator.validate(generateAuthRequest(signedJWT));

        assertTrue(requestObjectError.isPresent());
        assertThat(requestObjectError.get().errorObject(), equalTo(OAuth2Error.INVALID_SCOPE));
        assertThat(requestObjectError.get().redirectURI().toString(), equalTo(REDIRECT_URI));
        assertEquals(STATE, requestObjectError.get().state());
    }

    @Test
    void shouldReturnErrorWhenAuthRequestContainsInvalidScope()
            throws JOSEException, JwksException, ClientSignatureValidationException {
        var jwtClaimsSet = getDefaultJWTClaimsSetBuilder().build();
        var signedJWT = generateSignedJWT(jwtClaimsSet, keyPair);

        var requestObjectError =
                validator.validate(
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
        var jwtClaimsSet = getDefaultJWTClaimsSetBuilder().claim("scope", "openid email").build();
        var authRequest = generateAuthRequest(generateSignedJWT(jwtClaimsSet, keyPair));
        var requestObjectError = validator.validate(authRequest);

        assertTrue(requestObjectError.isPresent());
        assertThat(requestObjectError.get().errorObject(), equalTo(OAuth2Error.INVALID_SCOPE));
        assertThat(requestObjectError.get().redirectURI().toString(), equalTo(REDIRECT_URI));
        assertEquals(STATE, requestObjectError.get().state());
    }

    @Test
    void shouldReturnErrorForInvalidAudience()
            throws JOSEException, JwksException, ClientSignatureValidationException {
        var jwtClaimsSet = getDefaultJWTClaimsSetBuilder().audience("invalid-audience").build();

        var authRequest = generateAuthRequest(generateSignedJWT(jwtClaimsSet, keyPair));
        var requestObjectError = validator.validate(authRequest);

        assertTrue(requestObjectError.isPresent());
        assertThat(requestObjectError.get().errorObject(), equalTo(OAuth2Error.ACCESS_DENIED));
        assertThat(requestObjectError.get().redirectURI().toString(), equalTo(REDIRECT_URI));
        assertEquals(STATE, requestObjectError.get().state());
    }

    @Test
    void shouldReturnErrorForInvalidIssuer()
            throws JOSEException, JwksException, ClientSignatureValidationException {
        var jwtClaimsSet = getDefaultJWTClaimsSetBuilder().issuer("invalid-client").build();
        var authRequest = generateAuthRequest(generateSignedJWT(jwtClaimsSet, keyPair));
        var requestObjectError = validator.validate(authRequest);

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
                getDefaultJWTClaimsSetBuilder()
                        .claim("request", "some-random-request-value")
                        .build();
        generateSignedJWT(jwtClaimsSet, keyPair);
        var authRequest = generateAuthRequest(generateSignedJWT(jwtClaimsSet, keyPair));
        var requestObjectError = validator.validate(authRequest);

        assertTrue(requestObjectError.isPresent());
        assertThat(requestObjectError.get().errorObject(), equalTo(OAuth2Error.INVALID_REQUEST));
        assertThat(requestObjectError.get().redirectURI().toString(), equalTo(REDIRECT_URI));
        assertEquals(STATE, requestObjectError.get().state());
    }

    @Test
    void shouldReturnErrorIfRequestUriClaimIsPresentJwt()
            throws JOSEException, JwksException, ClientSignatureValidationException {
        var jwtClaimsSet =
                getDefaultJWTClaimsSetBuilder()
                        .claim("request_uri", URI.create("https://localhost/request_uri"))
                        .build();
        var authRequest = generateAuthRequest(generateSignedJWT(jwtClaimsSet, keyPair));
        var requestObjectError = validator.validate(authRequest);

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
        var jwtClaimsSet = getDefaultJWTClaimsSetBuilder().build();
        var authRequest = generateAuthRequest(generateSignedJWT(jwtClaimsSet, keyPair2));
        doThrow(new RuntimeException())
                .when(clientSignatureValidationService)
                .validate(any(SignedJWT.class), any(ClientRegistry.class));
        assertThrows(
                RuntimeException.class,
                () -> validator.validate(authRequest),
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

        var requestObjectError = validator.validate(generateAuthRequest(signedJWT));

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

        var jwtClaimsSet =
                new JWTClaimsSet.Builder()
                        .audience(OIDC_BASE_AUTHORIZE_URI.toString())
                        .claim("redirect_uri", REDIRECT_URI)
                        .claim("response_type", ResponseType.CODE.toString())
                        .claim("scope", SCOPE)
                        .claim("state", STATE.toString())
                        .claim("client_id", CLIENT_ID.getValue())
                        .claim("vtr", List.of("P2.Cl.Cm"))
                        .issuer(CLIENT_ID.getValue())
                        .build();
        var signedJWT = generateSignedJWT(jwtClaimsSet, keyPair);

        AuthenticationRequest authenticationRequest =
                new AuthenticationRequest.Builder(
                                ResponseType.CODE,
                                Scope.parse(SCOPE),
                                CLIENT_ID,
                                URI.create(REDIRECT_URI))
                        .state(STATE)
                        .requestObject(signedJWT)
                        .build();

        var requestObjectError = validator.validate(authenticationRequest);

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

        var requestObjectError = validator.validate(generateAuthRequest(signedJWT));

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
        var jwtClaimsSet = getDefaultJWTClaimsSetBuilder().claim("ui_locales", "123456").build();
        var authRequest = generateAuthRequest(generateSignedJWT(jwtClaimsSet, keyPair));
        var requestObjectError = validator.validate(authRequest);

        assertTrue(requestObjectError.isPresent());
        assertThat(requestObjectError.get().errorObject(), equalTo(OAuth2Error.INVALID_REQUEST));
        assertThat(requestObjectError.get().redirectURI().toString(), equalTo(REDIRECT_URI));
        assertEquals(STATE, requestObjectError.get().state());
    }

    @Test
    void shouldReturnErrorForNegativeMaxAgeString()
            throws JOSEException, JwksException, ClientSignatureValidationException {
        var jwtClaimsSet = getDefaultJWTClaimsSetBuilder().claim("max_age", "-5").build();
        var authRequest = generateAuthRequest(generateSignedJWT(jwtClaimsSet, keyPair));
        var requestObjectError = validator.validate(authRequest);

        assertTrue(requestObjectError.isPresent());
        assertThat(requestObjectError.get().errorObject(), equalTo(OAuth2Error.INVALID_REQUEST));
        assertThat(requestObjectError.get().redirectURI().toString(), equalTo(REDIRECT_URI));
        assertEquals(STATE, requestObjectError.get().state());
    }

    @Test
    void shouldReturnErrorForInvalidMaxAgeString()
            throws JOSEException, JwksException, ClientSignatureValidationException {
        var jwtClaimsSet = getDefaultJWTClaimsSetBuilder().claim("max_age", "NotANumber").build();
        var authRequest = generateAuthRequest(generateSignedJWT(jwtClaimsSet, keyPair));
        var requestObjectError = validator.validate(authRequest);

        assertTrue(requestObjectError.isPresent());
        assertThat(requestObjectError.get().errorObject(), equalTo(OAuth2Error.INVALID_REQUEST));
        assertThat(requestObjectError.get().redirectURI().toString(), equalTo(REDIRECT_URI));
        assertEquals(STATE, requestObjectError.get().state());
    }

    @Test
    void shouldReturnErrorForNegativedMaxAgeInteger()
            throws JOSEException, JwksException, ClientSignatureValidationException {
        var jwtClaimsSet = getDefaultJWTClaimsSetBuilder().claim("max_age", -5).build();
        var authRequest = generateAuthRequest(generateSignedJWT(jwtClaimsSet, keyPair));
        var requestObjectError = validator.validate(authRequest);

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
                getDefaultJWTClaimsSetBuilder().claim("claims", claimSet.toJSONString()).build();
        var authRequest = generateAuthRequest(generateSignedJWT(jwtClaimsSet, keyPair));
        var requestObjectError = validator.validate(authRequest);

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
                getDefaultJWTClaimsSetBuilder().claim("claims", claimSet.toJSONString()).build();
        var authRequest = generateAuthRequest(generateSignedJWT(jwtClaimsSet, keyPair));
        var requestObjectError = validator.validate(authRequest);

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
                getDefaultJWTClaimsSetBuilder().claim("claims", claimSet.toJSONObject()).build();
        var authRequest = generateAuthRequest(generateSignedJWT(jwtClaimsSet, keyPair));
        var requestObjectError = validator.validate(authRequest);

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
                getDefaultJWTClaimsSetBuilder().claim("claims", claimSet.toJSONObject()).build();
        var authRequest = generateAuthRequest(generateSignedJWT(jwtClaimsSet, keyPair));
        var requestObjectError = validator.validate(authRequest);

        assertTrue(requestObjectError.isPresent());
        assertThat(requestObjectError.get().errorObject(), equalTo(OAuth2Error.INVALID_REQUEST));
        assertThat(requestObjectError.get().redirectURI().toString(), equalTo(REDIRECT_URI));
        assertEquals(STATE, requestObjectError.get().state());
    }

    private static Stream<Arguments> invalidChannelAttributes() {
        return Stream.of(
                Arguments.of(""),
                Arguments.of(Channel.STRATEGIC_APP.getValue()),
                Arguments.of("not-a-channel"));
    }

    @ParameterizedTest
    @MethodSource("invalidChannelAttributes")
    void shouldReturnErrorWhenInvalidChannelIsSentInRequest(String invalidChannel)
            throws JOSEException, JwksException, ClientSignatureValidationException {
        var jwtClaimsSet = getDefaultJWTClaimsSetBuilder().claim("channel", invalidChannel).build();
        var signedJWT = generateSignedJWT(jwtClaimsSet, keyPair);
        var authRequest = generateAuthRequest(signedJWT);

        var requestObjectError = validator.validate(authRequest);

        assertTrue(requestObjectError.isPresent());
        assertThat(requestObjectError.get().errorObject(), equalTo(OAuth2Error.INVALID_REQUEST));
        assertThat(requestObjectError.get().redirectURI().toString(), equalTo(REDIRECT_URI));
        assertEquals(STATE, requestObjectError.get().state());
    }

    private static Stream<Arguments> validChannelAttributes() {
        return Stream.of(
                Arguments.of(Channel.WEB.getValue()), Arguments.of(Channel.GENERIC_APP.getValue()));
    }

    @ParameterizedTest
    @MethodSource("validChannelAttributes")
    void shouldSuccessfullyValidateWhenValidChannelIsSentInRequest(String validChannel)
            throws JOSEException, JwksException, ClientSignatureValidationException {
        var jwtClaimsSet = getDefaultJWTClaimsSetBuilder().claim("channel", validChannel).build();
        var signedJWT = generateSignedJWT(jwtClaimsSet, keyPair);
        var authRequest = generateAuthRequest(signedJWT);
        var requestObjectError = validator.validate(authRequest);
        assertFalse(requestObjectError.isPresent());
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

    private JWTClaimsSet.Builder getDefaultJWTClaimsSetBuilder() {
        return new JWTClaimsSet.Builder()
                .audience(OIDC_BASE_AUTHORIZE_URI.toString())
                .claim("redirect_uri", REDIRECT_URI)
                .claim("response_type", ResponseType.CODE.toString())
                .claim("scope", SCOPE)
                .claim("nonce", NONCE.getValue())
                .claim("state", STATE.toString())
                .claim("client_id", CLIENT_ID.getValue())
                .issuer(CLIENT_ID.getValue());
    }
}
