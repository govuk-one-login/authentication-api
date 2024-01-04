package uk.gov.di.authentication.ipv.services;

import com.google.gson.GsonBuilder;
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
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.OIDCClaimsRequest;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import com.nimbusds.openid.connect.sdk.claims.ClaimRequirement;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSetRequest;
import org.approvaltests.JsonApprovals;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.model.SignRequest;
import software.amazon.awssdk.services.kms.model.SignResponse;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;
import uk.gov.di.orchestration.shared.helpers.IdGenerator;
import uk.gov.di.orchestration.shared.serialization.Json;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.KmsConnectionService;
import uk.gov.di.orchestration.shared.services.RedisConnectionService;
import uk.gov.di.orchestration.shared.services.SerializationService;
import uk.gov.di.orchestration.sharedtest.helper.TestClockHelper;

import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.text.ParseException;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static java.util.Collections.emptyList;
import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static uk.gov.di.authentication.ipv.services.IPVAuthorisationService.STATE_STORAGE_PREFIX;

class IPVAuthorisationServiceTest {

    private static final AuthorizationCode AUTH_CODE = new AuthorizationCode();
    private static final State STATE = new State();
    private static final String SESSION_ID = "session-id";
    private static final Long SESSION_EXPIRY = 3600L;
    private static final String KEY_ID = "14342354354353";
    private static final String IPV_CLIENT_ID = "ipv-client-id";
    private static final URI IPV_URI = URI.create("http://ipv/");
    private static final URI IPV_CALLBACK_URI = URI.create("http://localhost/oidc/ipv/callback");
    private static final URI IPV_AUTHORISATION_URI = URI.create("http://localhost/ipv/authorize");
    private static final Json objectMapper = SerializationService.getInstance();

    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final RedisConnectionService redisConnectionService =
            mock(RedisConnectionService.class);
    private final KmsConnectionService kmsConnectionService = mock(KmsConnectionService.class);
    private final IPVAuthorisationService authorisationService =
            new IPVAuthorisationService(
                    configurationService,
                    redisConnectionService,
                    kmsConnectionService,
                    TestClockHelper.getInstance());
    private PrivateKey privateKey;

    @BeforeEach
    void setUp() throws Json.JsonException {
        when(configurationService.getSessionExpiry()).thenReturn(SESSION_EXPIRY);
        when(redisConnectionService.getValue(STATE_STORAGE_PREFIX + SESSION_ID))
                .thenReturn(objectMapper.writeValueAsString(STATE));
        when(configurationService.getIPVAuthorisationClientId()).thenReturn(IPV_CLIENT_ID);
        when(configurationService.getIPVAuthorisationCallbackURI()).thenReturn(IPV_CALLBACK_URI);
        when(configurationService.getIPVAuthorisationURI()).thenReturn(IPV_AUTHORISATION_URI);
        when(configurationService.getIPVAudience()).thenReturn(IPV_URI.toString());
        var keyPair = generateRsaKeyPair();
        privateKey = keyPair.getPrivate();
        var certpem =
                "-----BEGIN PUBLIC KEY-----\n"
                        + Base64.getMimeEncoder().encodeToString(keyPair.getPublic().getEncoded())
                        + "\n-----END PUBLIC KEY-----\n";
        when(configurationService.getIPVAuthEncryptionPublicKey()).thenReturn(certpem);
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
            throws Json.JsonException {
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
    void shouldSaveStateToRedis() throws Json.JsonException {
        var sessionId = "session-id";
        authorisationService.storeState(sessionId, STATE);

        verify(redisConnectionService)
                .saveWithExpiry(
                        STATE_STORAGE_PREFIX + sessionId,
                        objectMapper.writeValueAsString(STATE),
                        SESSION_EXPIRY);
    }

    @Nested
    class SignedJwtRequest {
        @BeforeEach
        void beforeEach() throws JOSEException {
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
            byte[] signatureToDER =
                    ECDSA.transcodeSignatureToDER(signedJWT.getSignature().decode());
            var signResult =
                    SignResponse.builder()
                            .signature(SdkBytes.fromByteArray(signatureToDER))
                            .keyId(KEY_ID)
                            .signingAlgorithm(SigningAlgorithmSpec.ECDSA_SHA_256)
                            .build();
            when(kmsConnectionService.sign(any(SignRequest.class))).thenReturn(signResult);
            when(configurationService.isAccountInterventionServiceCallEnabled()).thenReturn(true);
            when(configurationService.isAccountInterventionServiceActionEnabled()).thenReturn(true);
        }

        @Test
        void shouldConstructASignedRequestJWT() throws JOSEException, ParseException {
            var state = new State("test-state");
            var scope = new Scope(OIDCScopeValue.OPENID);
            var pairwise = new Subject("pairwise-identifier");
            var claims =
                    new ClaimsSetRequest()
                            .add(
                                    new ClaimsSetRequest.Entry(
                                                    "https://vocab.account.gov.uk/v1/coreIdentityJWT")
                                            .withClaimRequirement(ClaimRequirement.ESSENTIAL))
                            .add(
                                    new ClaimsSetRequest.Entry(
                                            "https://vocab.account.gov.uk/v1/address"));

            EncryptedJWT encryptedJWT;
            try (var mockIdGenerator = mockStatic(IdGenerator.class)) {
                mockIdGenerator.when(IdGenerator::generate).thenReturn("test-jti");
                encryptedJWT =
                        authorisationService.constructRequestJWT(
                                state,
                                scope,
                                pairwise,
                                claims,
                                "journey-id",
                                "test@test.com",
                                List.of("Cl.Cm.P2", "Cl.Cm.PCL200"),
                                true);
            }

            var signedJWTResponse = decryptJWT(encryptedJWT);

            JsonApprovals.verifyAsJson(
                    signedJWTResponse.getJWTClaimsSet().toJSONObject(),
                    GsonBuilder::serializeNulls);

            assertThat(
                    signedJWTResponse.getJWTClaimsSet().getClaim("client_id"),
                    equalTo(IPV_CLIENT_ID));
            assertThat(
                    signedJWTResponse.getJWTClaimsSet().getClaim("state"),
                    equalTo(state.getValue()));
            assertThat(
                    signedJWTResponse.getJWTClaimsSet().getSubject(), equalTo(pairwise.getValue()));
            assertThat(
                    signedJWTResponse.getJWTClaimsSet().getClaim("scope"),
                    equalTo(scope.toString()));
            assertThat(signedJWTResponse.getJWTClaimsSet().getIssuer(), equalTo(IPV_CLIENT_ID));
            assertThat(
                    signedJWTResponse.getJWTClaimsSet().getAudience(),
                    equalTo(singletonList(IPV_URI.toString())));
            assertThat(
                    signedJWTResponse.getJWTClaimsSet().getClaim("response_type"), equalTo("code"));
            var expectedClaimsRequest =
                    new OIDCClaimsRequest().withUserInfoClaimsRequest(claims).toJSONObject();
            assertThat(
                    signedJWTResponse.getJWTClaimsSet().getClaim("claims"),
                    equalTo(expectedClaimsRequest));
            assertThat(
                    signedJWTResponse.getJWTClaimsSet().getClaim("email_address"),
                    equalTo("test@test.com"));
            assertThat(
                    signedJWTResponse.getJWTClaimsSet().getClaim("govuk_signin_journey_id"),
                    equalTo("journey-id"));
            assertThat(
                    signedJWTResponse.getJWTClaimsSet().getClaim("vtr"),
                    equalTo(List.of("Cl.Cm.P2", "Cl.Cm.PCL200")));
            assertThat(
                    signedJWTResponse.getJWTClaimsSet().getClaim("reprove_identity"),
                    equalTo(true));
        }

        @Test
        void shouldConstructJWTWithCorrectReproveIdentityClaimFromFlag()
                throws JOSEException, ParseException {
            EncryptedJWT encryptedJWT;
            try (var mockIdGenerator = mockStatic(IdGenerator.class)) {
                mockIdGenerator.when(IdGenerator::generate).thenReturn("test-jti");
                encryptedJWT =
                        authorisationService.constructRequestJWT(
                                new State("state"),
                                new Scope(OIDCScopeValue.OPENID),
                                new Subject("subject"),
                                new ClaimsSetRequest(),
                                "",
                                "",
                                emptyList(),
                                false);
            }

            var signedJWTResponse = decryptJWT(encryptedJWT);

            assertThat(
                    signedJWTResponse.getJWTClaimsSet().getClaim("reprove_identity"),
                    equalTo(false));
        }

        @Test
        void shouldNotConstructJWTWithReproveIdentityClaimIfAccountInterventionsActionFlagDisabled()
                throws JOSEException, ParseException {
            when(configurationService.isAccountInterventionServiceActionEnabled())
                    .thenReturn(false);
            EncryptedJWT encryptedJWT;

            try (var mockIdGenerator = mockStatic(IdGenerator.class)) {
                mockIdGenerator.when(IdGenerator::generate).thenReturn("test-jti");
                encryptedJWT =
                        authorisationService.constructRequestJWT(
                                new State("state"),
                                new Scope(OIDCScopeValue.OPENID),
                                new Subject("subject"),
                                new ClaimsSetRequest(),
                                "",
                                "",
                                emptyList(),
                                false);
            }
            var signedJWTResponse = decryptJWT(encryptedJWT);

            assertFalse(
                    signedJWTResponse
                            .getJWTClaimsSet()
                            .getClaims()
                            .containsKey("reprove_identity"));
        }

        @Test
        void shouldNotConstructJWTWithReproveIdentityClaimIfReproveIdentityIsNull()
                throws JOSEException, ParseException {
            EncryptedJWT encryptedJWT;

            try (var mockIdGenerator = mockStatic(IdGenerator.class)) {
                mockIdGenerator.when(IdGenerator::generate).thenReturn("test-jti");
                encryptedJWT =
                        authorisationService.constructRequestJWT(
                                new State("state"),
                                new Scope(OIDCScopeValue.OPENID),
                                new Subject("subject"),
                                new ClaimsSetRequest(),
                                "",
                                "",
                                emptyList(),
                                null);
            }
            var signedJWTResponse = decryptJWT(encryptedJWT);

            assertFalse(
                    signedJWTResponse
                            .getJWTClaimsSet()
                            .getClaims()
                            .containsKey("reprove_identity"));
        }
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
