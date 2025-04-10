package uk.gov.di.authentication.oidc.services;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.impl.ECDSA;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
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
import org.mockito.ArgumentCaptor;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.model.MessageType;
import software.amazon.awssdk.services.kms.model.SignRequest;
import software.amazon.awssdk.services.kms.model.SignResponse;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;
import uk.gov.di.orchestration.shared.entity.ClientRegistry;
import uk.gov.di.orchestration.shared.exceptions.ClientNotFoundException;
import uk.gov.di.orchestration.shared.helpers.CookieHelper;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.DynamoClientService;
import uk.gov.di.orchestration.shared.services.KmsConnectionService;
import uk.gov.di.orchestration.shared.services.NoSessionOrchestrationService;
import uk.gov.di.orchestration.shared.services.RedisConnectionService;
import uk.gov.di.orchestration.sharedtest.logging.CaptureLoggingExtension;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
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
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.orchestration.shared.helpers.PersistentIdHelper.isValidPersistentSessionCookieWithDoubleDashedTimestamp;
import static uk.gov.di.orchestration.sharedtest.helper.JsonArrayHelper.jsonArrayOf;
import static uk.gov.di.orchestration.sharedtest.logging.LogEventMatcher.withMessageContaining;

class OrchestrationAuthorizationServiceTest {

    private static final URI REDIRECT_URI = URI.create("http://localhost/redirect");
    private static final ClientID CLIENT_ID = new ClientID();
    private static final State STATE = new State();
    private static final Nonce NONCE = new Nonce();
    private static final String KEY_ID = "14342354354353";
    // 5000 Chars long
    private static final String LONG_CLAIM =
            "11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111";
    private OrchestrationAuthorizationService orchestrationAuthorizationService;
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final DynamoClientService dynamoClientService = mock(DynamoClientService.class);
    private final IPVCapacityService ipvCapacityService = mock(IPVCapacityService.class);
    private final KmsConnectionService kmsConnectionService = mock(KmsConnectionService.class);
    private final RedisConnectionService redisConnectionService =
            mock(RedisConnectionService.class);
    private final NoSessionOrchestrationService noSessionOrchestrationService =
            mock(NoSessionOrchestrationService.class);
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
                        redisConnectionService,
                        noSessionOrchestrationService);
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
        var expectedMessage =
                jwsHeader.toBase64URL() + "." + Base64URL.encode(jwtClaimsSet.toString());
        var signResult =
                SignResponse.builder()
                        .signature(SdkBytes.fromByteArray(signatureToDER))
                        .keyId(KEY_ID)
                        .signingAlgorithm(SigningAlgorithmSpec.ECDSA_SHA_256)
                        .build();
        when(kmsConnectionService.sign(any(SignRequest.class))).thenReturn(signResult);

        var encryptedJWT = orchestrationAuthorizationService.getSignedAndEncryptedJWT(jwtClaimsSet);

        var signedJWTResponse = decryptJWT(encryptedJWT);
        var signRequestCaptor = ArgumentCaptor.forClass(SignRequest.class);
        assertThat(signedJWTResponse.getJWTClaimsSet().getClaim("claim1"), equalTo(claim1Value));
        verify(kmsConnectionService).sign(signRequestCaptor.capture());
        assertThat(
                SdkBytes.fromByteArray(expectedMessage.getBytes(StandardCharsets.UTF_8)),
                equalTo(signRequestCaptor.getValue().message()));
        assertThat(MessageType.RAW, equalTo(signRequestCaptor.getValue().messageType()));
    }

    @Test
    void shouldUseAHashDigestWhenMessageSizeIsMoreThan4095() throws JOSEException, ParseException {
        var claim1Value = "JWT claim 1";
        var ecSigningKey =
                new ECKeyGenerator(Curve.P_256)
                        .keyID(KEY_ID)
                        .algorithm(JWSAlgorithm.ES256)
                        .generate();
        var ecdsaSigner = new ECDSASigner(ecSigningKey);
        var jwtClaimsSet =
                new JWTClaimsSet.Builder()
                        .claim("claim1", claim1Value)
                        .claim("state", LONG_CLAIM)
                        .build();
        var jwsHeader = new JWSHeader(JWSAlgorithm.ES256);
        var signedJWT = new SignedJWT(jwsHeader, jwtClaimsSet);
        var expectedMessage =
                jwsHeader.toBase64URL() + "." + Base64URL.encode(jwtClaimsSet.toString());
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

        var signRequestCaptor = ArgumentCaptor.forClass(SignRequest.class);
        var signedJWTResponse = decryptJWT(encryptedJWT);
        assertThat(signedJWTResponse.getJWTClaimsSet().getClaim("claim1"), equalTo(claim1Value));
        assertThat(signedJWTResponse.getJWTClaimsSet().getClaim("state"), equalTo(LONG_CLAIM));
        signedJWTResponse.verify(new ECDSAVerifier(ecSigningKey.toECPublicKey()));
        verify(kmsConnectionService).sign(signRequestCaptor.capture());
        assertThat(
                getHashSdkBytes(expectedMessage), equalTo(signRequestCaptor.getValue().message()));
        assertThat(MessageType.DIGEST, equalTo(signRequestCaptor.getValue().messageType()));
    }

    @Test
    void shouldSaveStateInRedis() {
        when(configurationService.getSessionExpiry()).thenReturn(3600L);
        var sessionId = "new-session-id";
        var clientSessionId = "new-client-session-id";
        var state = new State();

        orchestrationAuthorizationService.storeState(sessionId, clientSessionId, state);

        verify(redisConnectionService)
                .saveWithExpiry("auth-state:" + sessionId, state.getValue(), 3600);
        verify(noSessionOrchestrationService)
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

    private SdkBytes getHashSdkBytes(String jwtMessage) {
        byte[] signingInputHash;
        try {
            signingInputHash =
                    MessageDigest.getInstance("SHA-256")
                            .digest(jwtMessage.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e.getMessage());
        }
        return SdkBytes.fromByteArray(signingInputHash);
    }
}
