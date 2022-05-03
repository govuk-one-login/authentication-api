package uk.gov.di.authentication.app.services;

import com.amazonaws.services.kms.model.SignRequest;
import com.amazonaws.services.kms.model.SignResult;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
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
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.helpers.ObjectMapperFactory;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.KmsConnectionService;
import uk.gov.di.authentication.shared.services.RedisConnectionService;

import java.net.URI;
import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.text.ParseException;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.app.services.DocAppAuthorisationService.STATE_STORAGE_PREFIX;

class DocAppAuthorisationServiceTest {

    private static final AuthorizationCode AUTH_CODE = new AuthorizationCode();
    private static final State STATE = new State();
    private static final String SESSION_ID = "session-id";
    private static final Long SESSION_EXPIRY = 3600L;
    private static final String KEY_ID = "14342354354353";
    private static final String DOC_APP_CLIENT_ID = "doc-app-client-id";
    private static final URI DOC_APP_CALLBACK_URI =
            URI.create("http://localhost/oidc/doc-app/callback");
    private static final URI DOC_APP_AUTHORISATION_URI =
            URI.create("http://localhost/doc-app/authorize");
    private static final ObjectMapper objectMapper = ObjectMapperFactory.getInstance();

    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final RedisConnectionService redisConnectionService =
            mock(RedisConnectionService.class);
    private final KmsConnectionService kmsConnectionService = mock(KmsConnectionService.class);
    private final DocAppAuthorisationService authorisationService =
            new DocAppAuthorisationService(
                    configurationService, redisConnectionService, kmsConnectionService);
    private PrivateKey privateKey;

    @BeforeEach
    void setUp() throws JsonProcessingException {
        when(configurationService.getSessionExpiry()).thenReturn(SESSION_EXPIRY);
        when(redisConnectionService.getValue(STATE_STORAGE_PREFIX + SESSION_ID))
                .thenReturn(objectMapper.writeValueAsString(STATE));
        when(configurationService.getDocAppAuthorisationClientId()).thenReturn(DOC_APP_CLIENT_ID);
        when(configurationService.getDocAppAuthorisationCallbackURI())
                .thenReturn(DOC_APP_CALLBACK_URI);
        when(configurationService.getDocAppAuthorisationURI())
                .thenReturn(DOC_APP_AUTHORISATION_URI);
        var keyPair = generateRsaKeyPair();
        privateKey = keyPair.getPrivate();
        var certpem =
                "-----BEGIN PUBLIC KEY-----\n"
                        + Base64.getMimeEncoder().encodeToString(keyPair.getPublic().getEncoded())
                        + "\n-----END PUBLIC KEY-----\n";
        when(configurationService.getDocAppAuthEncryptionPublicKey()).thenReturn(certpem);
    }

    @Test
    void shouldReturnOptionalEmptyWhenNoErrorIsPresent() {
        Map<String, String> responseHeaders = new HashMap<>();
        responseHeaders.put("code", AUTH_CODE.getValue());
        responseHeaders.put("state", STATE.getValue());

        assertThat(
                authorisationService.validateResponse(responseHeaders, SESSION_ID),
                equalTo(Optional.empty()));
    }

    @Test
    void shouldReturnErrorObjectWhenResponseContainsError() {
        ErrorObject errorObject =
                new ErrorObject(
                        "invalid_request_redirect_uri", "redirect_uri param must be provided");
        Map<String, String> responseHeaders = new HashMap<>();
        responseHeaders.put("code", AUTH_CODE.getValue());
        responseHeaders.put("state", STATE.getValue());
        responseHeaders.put("error", errorObject.toString());

        assertThat(
                authorisationService.validateResponse(responseHeaders, SESSION_ID),
                equalTo(Optional.of(new ErrorObject(errorObject.getCode()))));
    }

    @Test
    void shouldReturnErrorObjectWhenResponseContainsNoQueryParams() {
        assertThat(
                authorisationService.validateResponse(Collections.emptyMap(), SESSION_ID),
                equalTo(
                        Optional.of(
                                new ErrorObject(
                                        OAuth2Error.INVALID_REQUEST_CODE,
                                        "No query parameters present"))));
    }

    @Test
    void shouldReturnErrorObjectWhenResponseContainsNoStateParam() {
        Map<String, String> responseHeaders = new HashMap<>();
        responseHeaders.put("code", AUTH_CODE.getValue());

        assertThat(
                authorisationService.validateResponse(responseHeaders, SESSION_ID),
                equalTo(
                        Optional.of(
                                new ErrorObject(
                                        OAuth2Error.INVALID_REQUEST_CODE,
                                        "No state param present in Authorisation response"))));
    }

    @Test
    void shouldReturnErrorObjectWhenResponseContainsNoCodeParam() {
        Map<String, String> responseHeaders = new HashMap<>();
        responseHeaders.put("state", STATE.getValue());

        assertThat(
                authorisationService.validateResponse(responseHeaders, SESSION_ID),
                equalTo(
                        Optional.of(
                                new ErrorObject(
                                        OAuth2Error.INVALID_REQUEST_CODE,
                                        "No code param present in Authorisation response"))));
    }

    @Test
    void shouldReturnErrorObjectWhenStateInResponseIsDifferentToStoredState()
            throws JsonProcessingException {
        State differentState = new State();
        when(redisConnectionService.getValue(STATE_STORAGE_PREFIX + SESSION_ID))
                .thenReturn(objectMapper.writeValueAsString(STATE));
        Map<String, String> responseHeaders = new HashMap<>();
        responseHeaders.put("state", differentState.getValue());
        responseHeaders.put("code", AUTH_CODE.getValue());

        assertThat(
                authorisationService.validateResponse(responseHeaders, SESSION_ID),
                equalTo(
                        Optional.of(
                                new ErrorObject(
                                        OAuth2Error.INVALID_REQUEST_CODE,
                                        "Invalid state param present in Authorisation response"))));
    }

    @Test
    void shouldSaveStateToRedis() throws JsonProcessingException {
        var sessionId = "session-id";
        authorisationService.storeState(sessionId, STATE);

        verify(redisConnectionService)
                .saveWithExpiry(
                        STATE_STORAGE_PREFIX + sessionId,
                        objectMapper.writeValueAsString(STATE),
                        SESSION_EXPIRY);
    }

    @Test
    void shouldConstructASignedRequestJWT() throws JOSEException, ParseException {
        var ecSigningKey =
                new ECKeyGenerator(Curve.P_256)
                        .keyID(KEY_ID)
                        .algorithm(JWSAlgorithm.ES256)
                        .generate();
        var ecdsaSigner = new ECDSASigner(ecSigningKey);
        var jwtClaimsSet = new JWTClaimsSet.Builder().build();
        var jwsHeader = new JWSHeader(JWSAlgorithm.ES256);
        var signedJWT = new SignedJWT(jwsHeader, jwtClaimsSet);
        signedJWT.sign(ecdsaSigner);
        var signResult = new SignResult();
        byte[] signatureToDER = ECDSA.transcodeSignatureToDER(signedJWT.getSignature().decode());
        signResult.setSignature(ByteBuffer.wrap(signatureToDER));
        signResult.setKeyId(KEY_ID);
        signResult.setSigningAlgorithm(JWSAlgorithm.ES256.getName());
        when(kmsConnectionService.sign(any(SignRequest.class))).thenReturn(signResult);
        var state = new State();
        var pairwise = new Subject("pairwise-identifier");

        var encryptedJWT = authorisationService.constructRequestJWT(state, pairwise);

        var signedJWTResponse = decryptJWT(encryptedJWT);

        assertThat(
                signedJWTResponse.getJWTClaimsSet().getClaim("client_id"),
                equalTo(DOC_APP_CLIENT_ID));
        assertThat(
                signedJWTResponse.getJWTClaimsSet().getClaim("state"), equalTo(state.getValue()));
        assertThat(signedJWTResponse.getJWTClaimsSet().getSubject(), equalTo(pairwise.getValue()));
        assertThat(signedJWTResponse.getJWTClaimsSet().getIssuer(), equalTo(DOC_APP_CLIENT_ID));
        assertThat(
                signedJWTResponse.getJWTClaimsSet().getAudience(),
                equalTo(singletonList(DOC_APP_AUTHORISATION_URI.toString())));
        assertThat(signedJWTResponse.getJWTClaimsSet().getClaim("response_type"), equalTo("code"));
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
