package uk.gov.di.authentication.oidc.services;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.impl.ECDSA;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
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
import com.nimbusds.openid.connect.sdk.OIDCClaimsRequest;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSetRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.model.SignRequest;
import software.amazon.awssdk.services.kms.model.SignResponse;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.CustomScopeValue;
import uk.gov.di.authentication.shared.entity.ValidClaims;
import uk.gov.di.authentication.shared.exceptions.ClientNotFoundException;
import uk.gov.di.authentication.shared.helpers.CookieHelper;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoClientService;
import uk.gov.di.authentication.shared.services.KmsConnectionService;
import uk.gov.di.authentication.shared.services.RedisConnectionService;
import uk.gov.di.authentication.sharedtest.logging.CaptureLoggingExtension;

import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.text.ParseException;
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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.sharedtest.helper.JsonArrayHelper.jsonArrayOf;
import static uk.gov.di.authentication.sharedtest.logging.LogEventMatcher.withMessageContaining;

class AuthorizationServiceTest {

    private static final URI REDIRECT_URI = URI.create("http://localhost/redirect");
    private static final ClientID CLIENT_ID = new ClientID();
    private static final State STATE = new State();
    private static final Nonce NONCE = new Nonce();
    private static final String KEY_ID = "14342354354353";
    private OrchestrationAuthorizationService orchestrationAuthorizationService;
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final DynamoClientService dynamoClientService = mock(DynamoClientService.class);
    private final IPVCapacityService ipvCapacityService = mock(IPVCapacityService.class);
    private final KmsConnectionService kmsConnectionService = mock(KmsConnectionService.class);
    private final RedisConnectionService redisConnectionService =
            mock(RedisConnectionService.class);
    private PrivateKey privateKey;

    @RegisterExtension
    public final CaptureLoggingExtension logging =
            new CaptureLoggingExtension(OrchestrationAuthorizationService.class);

    @BeforeEach
    void setUp() {
        orchestrationAuthorizationService =
                new OrchestrationAuthorizationService(
                        configurationService,
                        dynamoClientService,
                        ipvCapacityService,
                        kmsConnectionService,
                        redisConnectionService);
        var keyPair = generateRsaKeyPair();
        privateKey = keyPair.getPrivate();
        String publicCertificateAsPem =
                "-----BEGIN PUBLIC KEY-----\n"
                        + Base64.getMimeEncoder().encodeToString(keyPair.getPublic().getEncoded())
                        + "\n-----END PUBLIC KEY-----\n";
        when(configurationService.getOrchestrationToAuthenticationEncryptionPublicKey())
                .thenReturn(publicCertificateAsPem);
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
    void shouldSuccessfullyValidateAuthRequestWhenIdentityValuesAreIncludedInVtrAttribute()
            throws ParseException {
        when(ipvCapacityService.isIPVCapacityAvailable()).thenReturn(true);
        Scope scope = new Scope();
        scope.add(OIDCScopeValue.OPENID);
        when(dynamoClientService.getClient(CLIENT_ID.toString()))
                .thenReturn(
                        Optional.of(
                                generateClientRegistry(
                                        REDIRECT_URI.toString(), CLIENT_ID.toString())));
        ResponseType responseType = new ResponseType(ResponseType.Value.CODE);
        AuthenticationRequest authRequest =
                generateAuthRequest(
                        REDIRECT_URI.toString(),
                        responseType,
                        scope,
                        jsonArrayOf("P2.Cl.Cm"),
                        Optional.empty());
        var errorObject = orchestrationAuthorizationService.validateAuthRequest(authRequest, true);

        assertThat(errorObject, equalTo(Optional.empty()));
    }

    @Test
    void shouldReturnErrorWhenInvalidVtrAttributeIsSentInRequest() throws ParseException {
        Scope scope = new Scope();
        scope.add(OIDCScopeValue.OPENID);
        when(dynamoClientService.getClient(CLIENT_ID.toString()))
                .thenReturn(
                        Optional.of(
                                generateClientRegistry(
                                        REDIRECT_URI.toString(), CLIENT_ID.toString())));
        ResponseType responseType = new ResponseType(ResponseType.Value.CODE);
        AuthenticationRequest authRequest =
                generateAuthRequest(
                        REDIRECT_URI.toString(),
                        responseType,
                        scope,
                        jsonArrayOf("Cm.Cl.P1", "P1.Cl"),
                        Optional.empty());
        var errorObject = orchestrationAuthorizationService.validateAuthRequest(authRequest, true);

        assertTrue(errorObject.isPresent());

        assertThat(
                errorObject.get().errorObject(),
                equalTo(
                        new ErrorObject(
                                OAuth2Error.INVALID_REQUEST_CODE, "Request vtr not valid")));
    }

    @Test
    void shouldSuccessfullyValidateAuthRequest() throws ParseException {
        ResponseType responseType = new ResponseType(ResponseType.Value.CODE);
        Scope scope = new Scope();
        scope.add(OIDCScopeValue.OPENID);
        when(dynamoClientService.getClient(CLIENT_ID.toString()))
                .thenReturn(
                        Optional.of(
                                generateClientRegistry(
                                        REDIRECT_URI.toString(), CLIENT_ID.toString())));
        var errorObject =
                orchestrationAuthorizationService.validateAuthRequest(
                        generateAuthRequest(REDIRECT_URI.toString(), responseType, scope), true);

        assertTrue(errorObject.isEmpty());
    }

    @Test
    void shouldSuccessfullyValidateAuthRequestWhenNonceIsNotIncludedButOptionalButGivenEnvironment()
            throws ParseException {
        when(dynamoClientService.getClient(CLIENT_ID.toString()))
                .thenReturn(
                        Optional.of(
                                generateClientRegistry(
                                        REDIRECT_URI.toString(), CLIENT_ID.toString())));
        var authRequest =
                new AuthenticationRequest.Builder(
                                new ResponseType(ResponseType.Value.CODE),
                                new Scope(OIDCScopeValue.OPENID),
                                CLIENT_ID,
                                URI.create(REDIRECT_URI.toString()))
                        .state(STATE)
                        .build();
        var errorObject = orchestrationAuthorizationService.validateAuthRequest(authRequest, false);

        assertTrue(errorObject.isEmpty());
    }

    @Test
    void shouldSuccessfullyValidateAuthRequestWhenValidClaimsArePresent() throws ParseException {
        var scope = new Scope(OIDCScopeValue.OPENID);
        var clientRegistry =
                new ClientRegistry()
                        .withRedirectUrls(singletonList(REDIRECT_URI.toString()))
                        .withClientID(CLIENT_ID.toString())
                        .withScopes(scope.toStringList())
                        .withClaims(
                                List.of(
                                        ValidClaims.ADDRESS.getValue(),
                                        ValidClaims.CORE_IDENTITY_JWT.getValue()));
        when(dynamoClientService.getClient(CLIENT_ID.toString()))
                .thenReturn(Optional.of(clientRegistry));
        var claimsSetRequest =
                new ClaimsSetRequest()
                        .add(ValidClaims.ADDRESS.getValue())
                        .add(ValidClaims.CORE_IDENTITY_JWT.getValue());
        var oidcClaimsRequest = new OIDCClaimsRequest().withUserInfoClaimsRequest(claimsSetRequest);
        var authRequest =
                generateAuthRequest(
                        REDIRECT_URI.toString(),
                        new ResponseType(ResponseType.Value.CODE),
                        scope,
                        jsonArrayOf("Cl.Cm", "Cl"),
                        Optional.of(oidcClaimsRequest));
        var errorObject = orchestrationAuthorizationService.validateAuthRequest(authRequest, true);

        assertTrue(errorObject.isEmpty());
    }

    @Test
    void shouldReturnErrorWhenValidatingAuthRequestWhichContainsInvalidClaims()
            throws ParseException {
        ResponseType responseType = new ResponseType(ResponseType.Value.CODE);
        Scope scope = new Scope();
        scope.add(OIDCScopeValue.OPENID);
        when(dynamoClientService.getClient(CLIENT_ID.toString()))
                .thenReturn(
                        Optional.of(
                                generateClientRegistry(
                                        REDIRECT_URI.toString(), CLIENT_ID.toString())));
        var claimsSetRequest = new ClaimsSetRequest().add("nickname").add("birthdate");
        var oidcClaimsRequest = new OIDCClaimsRequest().withUserInfoClaimsRequest(claimsSetRequest);
        AuthenticationRequest authRequest =
                generateAuthRequest(
                        REDIRECT_URI.toString(),
                        responseType,
                        scope,
                        jsonArrayOf("Cl.Cm", "Cl"),
                        Optional.of(oidcClaimsRequest));
        var errorObject = orchestrationAuthorizationService.validateAuthRequest(authRequest, true);

        assertTrue(errorObject.isPresent());
        assertThat(
                errorObject.get().errorObject(),
                equalTo(
                        new ErrorObject(
                                OAuth2Error.INVALID_REQUEST_CODE,
                                "Request contains invalid claims")));
    }

    @Test
    void shouldSuccessfullyValidateAccountManagementAuthRequest() throws ParseException {
        ResponseType responseType = new ResponseType(ResponseType.Value.CODE);
        Scope scope = new Scope(OIDCScopeValue.OPENID, CustomScopeValue.ACCOUNT_MANAGEMENT);
        when(dynamoClientService.getClient(CLIENT_ID.toString()))
                .thenReturn(
                        Optional.of(
                                generateClientRegistry(
                                        REDIRECT_URI.toString(),
                                        CLIENT_ID.toString(),
                                        List.of("openid", "am"))));
        var errorObject =
                orchestrationAuthorizationService.validateAuthRequest(
                        generateAuthRequest(REDIRECT_URI.toString(), responseType, scope), true);

        assertTrue(errorObject.isEmpty());
    }

    @Test
    void shouldReturnErrorForAccountManagementAuthRequestWhenScopeNotInClient()
            throws ParseException {
        ResponseType responseType = new ResponseType(ResponseType.Value.CODE);
        Scope scope = new Scope(OIDCScopeValue.OPENID, CustomScopeValue.ACCOUNT_MANAGEMENT);
        when(dynamoClientService.getClient(CLIENT_ID.toString()))
                .thenReturn(
                        Optional.of(
                                generateClientRegistry(
                                        REDIRECT_URI.toString(), CLIENT_ID.toString())));
        var errorObject =
                orchestrationAuthorizationService.validateAuthRequest(
                        generateAuthRequest(REDIRECT_URI.toString(), responseType, scope), true);

        assertTrue(errorObject.isPresent());
        assertThat(errorObject.get().errorObject(), equalTo(OAuth2Error.INVALID_SCOPE));
    }

    @Test
    void shouldReturnErrorWhenClientIdIsNotValidInAuthRequest() {
        ResponseType responseType = new ResponseType(ResponseType.Value.CODE);
        Scope scope = new Scope();
        scope.add(OIDCScopeValue.OPENID);
        when(dynamoClientService.getClient(CLIENT_ID.toString())).thenReturn(Optional.empty());

        var runtimeException =
                assertThrows(
                        RuntimeException.class,
                        () ->
                                orchestrationAuthorizationService.validateAuthRequest(
                                        generateAuthRequest(
                                                REDIRECT_URI.toString(), responseType, scope),
                                        true),
                        "Expected to throw exception");

        assertThat(runtimeException.getMessage(), equalTo("No Client found with given ClientID"));
    }

    @Test
    void shouldReturnErrorWhenResponseCodeIsNotValidInAuthRequest() throws ParseException {
        ResponseType responseType =
                new ResponseType(ResponseType.Value.TOKEN, ResponseType.Value.CODE);
        Scope scope = new Scope();
        scope.add(OIDCScopeValue.OPENID);
        when(dynamoClientService.getClient(CLIENT_ID.toString()))
                .thenReturn(
                        Optional.of(
                                generateClientRegistry(
                                        REDIRECT_URI.toString(), CLIENT_ID.toString())));
        var errorObject =
                orchestrationAuthorizationService.validateAuthRequest(
                        generateAuthRequest(REDIRECT_URI.toString(), responseType, scope), true);

        assertTrue(errorObject.isPresent());
        assertThat(errorObject.get().errorObject(), equalTo(OAuth2Error.UNSUPPORTED_RESPONSE_TYPE));
    }

    @Test
    void shouldReturnErrorWhenScopeIsNotValidInAuthRequest() throws ParseException {
        ResponseType responseType = new ResponseType(ResponseType.Value.CODE);
        Scope scope = new Scope();
        scope.add(OIDCScopeValue.OPENID);
        scope.add(OIDCScopeValue.EMAIL);
        when(dynamoClientService.getClient(CLIENT_ID.toString()))
                .thenReturn(
                        Optional.of(
                                generateClientRegistry(
                                        REDIRECT_URI.toString(), CLIENT_ID.toString())));
        var errorObject =
                orchestrationAuthorizationService.validateAuthRequest(
                        generateAuthRequest(REDIRECT_URI.toString(), responseType, scope), true);

        assertTrue(errorObject.isPresent());
        assertThat(errorObject.get().errorObject(), equalTo(OAuth2Error.INVALID_SCOPE));
    }

    @Test
    void shouldReturnErrorWhenStateIsNotIncludedInAuthRequest() throws ParseException {
        ResponseType responseType = new ResponseType(ResponseType.Value.CODE);
        Scope scope = new Scope();
        scope.add(OIDCScopeValue.OPENID);
        when(dynamoClientService.getClient(CLIENT_ID.toString()))
                .thenReturn(
                        Optional.of(
                                generateClientRegistry(
                                        REDIRECT_URI.toString(), CLIENT_ID.toString())));
        AuthenticationRequest authRequest =
                new AuthenticationRequest.Builder(
                                responseType, scope, new ClientID(CLIENT_ID), REDIRECT_URI)
                        .nonce(new Nonce())
                        .build();
        var errorObject = orchestrationAuthorizationService.validateAuthRequest(authRequest, true);

        assertTrue(errorObject.isPresent());
        assertThat(
                errorObject.get().errorObject(),
                equalTo(
                        new ErrorObject(
                                OAuth2Error.INVALID_REQUEST_CODE,
                                "Request is missing state parameter")));
    }

    @Test
    void shouldReturnErrorWhenNonceIsNotIncludedInAuthRequest() throws ParseException {
        ResponseType responseType = new ResponseType(ResponseType.Value.CODE);
        Scope scope = new Scope();
        scope.add(OIDCScopeValue.OPENID);
        when(dynamoClientService.getClient(CLIENT_ID.toString()))
                .thenReturn(
                        Optional.of(
                                generateClientRegistry(
                                        REDIRECT_URI.toString(), CLIENT_ID.toString())));
        AuthenticationRequest authRequest =
                new AuthenticationRequest.Builder(
                                responseType, scope, new ClientID(CLIENT_ID), REDIRECT_URI)
                        .state(new State())
                        .build();
        var errorObject = orchestrationAuthorizationService.validateAuthRequest(authRequest, true);

        assertTrue(errorObject.isPresent());
        assertThat(
                errorObject.get().errorObject(),
                equalTo(
                        new ErrorObject(
                                OAuth2Error.INVALID_REQUEST_CODE,
                                "Request is missing nonce parameter")));
    }

    @Test
    void shouldReturnErrorWhenInvalidVtrIsIncludedInAuthRequest() throws ParseException {
        ResponseType responseType = new ResponseType(ResponseType.Value.CODE);
        Scope scope = new Scope();
        scope.add(OIDCScopeValue.OPENID);
        when(dynamoClientService.getClient(CLIENT_ID.toString()))
                .thenReturn(
                        Optional.of(
                                generateClientRegistry(
                                        REDIRECT_URI.toString(), CLIENT_ID.toString())));
        AuthenticationRequest authRequest =
                new AuthenticationRequest.Builder(responseType, scope, CLIENT_ID, REDIRECT_URI)
                        .state(new State())
                        .nonce(new Nonce())
                        .customParameter("vtr", jsonArrayOf("Cm"))
                        .build();
        var errorObject = orchestrationAuthorizationService.validateAuthRequest(authRequest, true);

        assertTrue(errorObject.isPresent());
        assertThat(
                errorObject.get().errorObject(),
                equalTo(
                        new ErrorObject(
                                OAuth2Error.INVALID_REQUEST_CODE, "Request vtr not valid")));
    }

    @Test
    void shouldReturnErrorWhenIdentityIsRequiredButNoIPVCapacityIsAvailable()
            throws ParseException {
        when(ipvCapacityService.isIPVCapacityAvailable()).thenReturn(false);
        var responseType = new ResponseType(ResponseType.Value.CODE);
        var scope = new Scope(OIDCScopeValue.OPENID);
        when(dynamoClientService.getClient(CLIENT_ID.toString()))
                .thenReturn(
                        Optional.of(
                                generateClientRegistry(
                                        REDIRECT_URI.toString(), CLIENT_ID.toString())));
        var authRequest =
                new AuthenticationRequest.Builder(responseType, scope, CLIENT_ID, REDIRECT_URI)
                        .state(new State())
                        .nonce(new Nonce())
                        .customParameter("vtr", jsonArrayOf("P2.Cl.Cm"))
                        .build();
        var errorObject = orchestrationAuthorizationService.validateAuthRequest(authRequest, true);

        assertTrue(errorObject.isPresent());
        assertThat(errorObject.get().errorObject(), equalTo(OAuth2Error.TEMPORARILY_UNAVAILABLE));
    }

    @Test
    void
            shouldNotReturnErrorWhenIdentityIsRequiredButNoIPVCapacityIsAvailableAndTheClientIsATestClient()
                    throws ParseException {
        when(ipvCapacityService.isIPVCapacityAvailable()).thenReturn(false);
        var responseType = new ResponseType(ResponseType.Value.CODE);
        var scope = new Scope(OIDCScopeValue.OPENID);
        when(dynamoClientService.getClient(CLIENT_ID.toString()))
                .thenReturn(
                        Optional.of(
                                generateClientRegistry(
                                        REDIRECT_URI.toString(),
                                        CLIENT_ID.toString(),
                                        singletonList("openid"),
                                        true)));
        var authRequest =
                new AuthenticationRequest.Builder(responseType, scope, CLIENT_ID, REDIRECT_URI)
                        .state(new State())
                        .nonce(new Nonce())
                        .customParameter("vtr", jsonArrayOf("P2.Cl.Cm"))
                        .build();
        var errorObject = orchestrationAuthorizationService.validateAuthRequest(authRequest, true);

        assertTrue(errorObject.isEmpty());
    }

    @Test
    void shouldThrowExceptionWhenRedirectUriIsInvalidInAuthRequest() {
        ResponseType responseType = new ResponseType(ResponseType.Value.CODE);
        String redirectURi = "http://localhost/redirect";
        Scope scope = new Scope();
        scope.add(OIDCScopeValue.OPENID);
        when(dynamoClientService.getClient(CLIENT_ID.toString()))
                .thenReturn(
                        Optional.of(
                                generateClientRegistry(
                                        "http://localhost/wrong-redirect", CLIENT_ID.toString())));

        var exception =
                assertThrows(
                        RuntimeException.class,
                        () ->
                                orchestrationAuthorizationService.validateAuthRequest(
                                        generateAuthRequest(redirectURi, responseType, scope),
                                        true),
                        "Expected to throw exception");
        assertThat(
                exception.getMessage(),
                equalTo(format("Invalid Redirect in request %s", redirectURi)));
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

        assertThat(persistentSessionId, equalTo("some-persistent-id"));
    }

    @Test
    void shouldReturnErrorWhenRequestURIIsPresent() throws ParseException {
        when(dynamoClientService.getClient(CLIENT_ID.toString()))
                .thenReturn(
                        Optional.of(
                                generateClientRegistry(
                                        REDIRECT_URI.toString(), CLIENT_ID.toString())));
        var authenticationRequest =
                new AuthenticationRequest.Builder(
                                new ResponseType(ResponseType.Value.CODE),
                                new Scope(OIDCScopeValue.OPENID),
                                CLIENT_ID,
                                REDIRECT_URI)
                        .requestURI(URI.create("https://localhost/redirect-uri"))
                        .build();

        var authRequestError =
                orchestrationAuthorizationService.validateAuthRequest(authenticationRequest, true);

        assertTrue(authRequestError.isPresent());
        assertThat(
                authRequestError.get().errorObject(),
                equalTo(OAuth2Error.REQUEST_URI_NOT_SUPPORTED));
    }

    @Test
    void shouldReturnErrorWhenRequestObjectIsPresent() throws ParseException {
        when(dynamoClientService.getClient(CLIENT_ID.toString()))
                .thenReturn(
                        Optional.of(
                                generateClientRegistry(
                                        REDIRECT_URI.toString(), CLIENT_ID.toString())));
        var authenticationRequest =
                new AuthenticationRequest.Builder(
                                new ResponseType(ResponseType.Value.CODE),
                                new Scope(OIDCScopeValue.OPENID),
                                CLIENT_ID,
                                REDIRECT_URI)
                        .requestObject(new PlainJWT(new JWTClaimsSet.Builder().build()))
                        .build();

        var authRequestError =
                orchestrationAuthorizationService.validateAuthRequest(authenticationRequest, true);

        assertTrue(authRequestError.isPresent());
        assertThat(
                authRequestError.get().errorObject(), equalTo(OAuth2Error.REQUEST_NOT_SUPPORTED));
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldIdentifyATestUserJourney(boolean dynamoClientServiceReturns) {
        when(dynamoClientService.isTestJourney(CLIENT_ID.toString(), "test@test.com"))
                .thenReturn(dynamoClientServiceReturns);

        assertThat(
                orchestrationAuthorizationService.isTestJourney(CLIENT_ID, "test@test.com"),
                equalTo(dynamoClientServiceReturns));
        assertThat(
                orchestrationAuthorizationService.isTestJourney(CLIENT_ID, "test@test.com"),
                equalTo(dynamoClientServiceReturns));
    }

    @Test
    void shouldConstructASignedAndEncryptedRequestJWT() throws JOSEException, ParseException {
        var claim1Value = "JWT claim 1";
        var ecSigningKey =
                new ECKeyGenerator(Curve.P_256)
                        .keyID(KEY_ID)
                        .algorithm(JWSAlgorithm.ES256)
                        .generate();
        var ecdsaSigner = new ECDSASigner(ecSigningKey);
        var jwtClaimsSet = new JWTClaimsSet.Builder().claim("claim1", claim1Value).build();
        var jwsHeader = new JWSHeader(JWSAlgorithm.ES256);
        var signedJWT = new SignedJWT(jwsHeader, jwtClaimsSet);
        signedJWT.sign(ecdsaSigner);
        byte[] signatureToDER = ECDSA.transcodeSignatureToDER(signedJWT.getSignature().decode());
        var signResult =
                SignResponse.builder()
                        .signature(SdkBytes.fromByteArray(signatureToDER))
                        .keyId(KEY_ID)
                        .signingAlgorithm(SigningAlgorithmSpec.ECDSA_SHA_256)
                        .build();
        when(kmsConnectionService.sign(any(SignRequest.class))).thenReturn(signResult);

        var encryptedJWT = orchestrationAuthorizationService.getSignedAndEncryptedJWT(jwtClaimsSet);

        var signedJWTResponse = decryptJWT(encryptedJWT);

        assertThat(signedJWTResponse.getJWTClaimsSet().getClaim("claim1"), equalTo(claim1Value));
    }

    @Test
    void shouldSaveStateInRedis() {
        when(configurationService.getSessionExpiry()).thenReturn(3600L);
        var sessionId = "new-session-id";
        var state = new State();

        orchestrationAuthorizationService.storeState(sessionId, state);

        verify(redisConnectionService)
                .saveWithExpiry("auth-state:" + sessionId, state.getValue(), 3600);
    }

    private ClientRegistry generateClientRegistry(String redirectURI, String clientID) {
        return generateClientRegistry(redirectURI, clientID, singletonList("openid"), false);
    }

    private ClientRegistry generateClientRegistry(
            String redirectURI, String clientID, List<String> scopes) {
        return generateClientRegistry(redirectURI, clientID, scopes, false);
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

    private SignedJWT decryptJWT(EncryptedJWT encryptedJWT) throws JOSEException {
        encryptedJWT.decrypt(new RSADecrypter(privateKey));
        return encryptedJWT.getPayload().toSignedJWT();
    }

    private KeyPair generateRsaKeyPair() {
        KeyPairGenerator kpg;
        try {
            kpg = KeyPairGenerator.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }
}
