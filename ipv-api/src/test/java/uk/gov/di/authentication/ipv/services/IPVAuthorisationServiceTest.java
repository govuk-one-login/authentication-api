package uk.gov.di.authentication.ipv.services;

import com.google.gson.GsonBuilder;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.impl.ECDSA;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
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
import org.approvaltests.Approvals;
import org.approvaltests.JsonApprovals;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.model.SignRequest;
import software.amazon.awssdk.services.kms.model.SignResponse;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;
import uk.gov.di.orchestration.shared.helpers.IdGenerator;
import uk.gov.di.orchestration.shared.serialization.Json;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.JwksService;
import uk.gov.di.orchestration.shared.services.KmsConnectionService;
import uk.gov.di.orchestration.shared.services.RedisConnectionService;
import uk.gov.di.orchestration.shared.services.SerializationService;
import uk.gov.di.orchestration.shared.services.StateStorageService;
import uk.gov.di.orchestration.sharedtest.helper.TestClockHelper;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static com.nimbusds.jose.JWSAlgorithm.RS256;
import static java.util.Collections.emptyList;
import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.ipv.services.IPVAuthorisationService.STATE_STORAGE_PREFIX;
import static uk.gov.di.orchestration.shared.helpers.HashHelper.hashSha256String;

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
    private static final String IPV_SIGNING_KEY_ID = "test-signing-key-id";
    private static final String SERIALIZED_JWT =
            "eyJraWQiOiIxZDUwNGFlY2UyOThhMTRkNzRlZTBhMDJiNjc0MGI0MzcyYTFmYWI0MjA2Nzc4ZTQ4NmJhNzI3NzBmZjRiZWI4IiwiYWxnIjoiRVMyNTYifQ.eyJhdWQiOlsiaHR0cHM6Ly9jcmVkZW50aWFsLXN0b3JlLmFjY291bnQuZ292LnVrIiwiaHR0cHM6Ly9pZGVudGl0eS50ZXN0LmFjY291bnQuZ292LnVrIl0sInN1YiI6InVybjpmZGM6Z292LnVrOjIwMjI6VEpMdDNXYWlHa0xoOFVxZWlzSDJ6VktHQVAwIiwic2NvcGUiOiJwcm92aW5nIiwiaXNzIjoiaHR0cHM6Ly9vaWRjLnRlc3QuYWNjb3VudC5nb3YudWsiLCJleHAiOjE3MTgxOTU3NjMsImlhdCI6MTcxODE5NTQ2MywianRpIjoiMWQyZTdmODgtYWIwNy00NWU5LThkYTAtOWEyMzIyMWFhZjM3In0.6MpC8IZbOICVjvf_97ySj6yOO6khQGhkEGHvYB6kXGMroSQgF0z0-Z1EVJi5sVXwmbe4X6eDRTIYtM07xItiMg";

    private static final Json objectMapper = SerializationService.getInstance();

    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final RedisConnectionService redisConnectionService =
            mock(RedisConnectionService.class);
    private final KmsConnectionService kmsConnectionService = mock(KmsConnectionService.class);
    private final JwksService jwksService = mock(JwksService.class);
    private final StateStorageService stateStorageService = mock(StateStorageService.class);
    private final IPVAuthorisationService authorisationService =
            new IPVAuthorisationService(
                    configurationService,
                    redisConnectionService,
                    kmsConnectionService,
                    jwksService,
                    TestClockHelper.getInstance(),
                    stateStorageService);
    private PrivateKey privateKey;

    @BeforeEach
    void setUp() throws Json.JsonException, MalformedURLException {
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
        var rsaKey =
                new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                        .keyUse(KeyUse.ENCRYPTION)
                        .keyID(KEY_ID)
                        .build();
        when(configurationService.getIPVJwksUrl())
                .thenReturn(new URL("http://localhost/.well-known/jwks.json"));
        when(jwksService.getIpvJwk()).thenReturn(rsaKey);
        when(configurationService.getIPVTokenSigningKeyAlias()).thenReturn(IPV_SIGNING_KEY_ID);
        when(jwksService.getPublicIpvTokenJwkWithOpaqueId())
                .thenReturn(
                        new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                                .keyID(hashSha256String(IPV_SIGNING_KEY_ID))
                                .keyUse(KeyUse.SIGNATURE)
                                .algorithm(RS256)
                                .build());
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

        @ParameterizedTest(name = "With useIpvJwksEndpointEnabled = {0}")
        @ValueSource(booleans = {true, false})
        void shouldConstructASignedRequestJWT(boolean useIpvJwksEndpoint)
                throws JOSEException, ParseException {
            when(configurationService.isUseIPVJwksEndpointEnabled()).thenReturn(useIpvJwksEndpoint);
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
                                            "https://vocab.account.gov.uk/v1/address"))
                            .add(
                                    new ClaimsSetRequest.Entry(
                                                    "https://vocab.account.gov.uk/v1/inheritedIdentityJWT")
                                            .withValues(List.of("jwt")))
                            .add(
                                    new ClaimsSetRequest.Entry(
                                                    "https://vocab.account.gov.uk/v1/storageAccessToken")
                                            .withValues(List.of(SERIALIZED_JWT)));

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
                                List.of("P2", "PCL200"),
                                true);
            }
            if (useIpvJwksEndpoint) {
                assertThat(encryptedJWT.getHeader().getKeyID(), equalTo(KEY_ID));
            }
            var signedJWTResponse = decryptJWT(encryptedJWT);

            JsonApprovals.verifyAsJson(
                    signedJWTResponse.getJWTClaimsSet().toJSONObject(),
                    GsonBuilder::serializeNulls,
                    Approvals.NAMES.withParameters(
                            useIpvJwksEndpoint ? "usingJwksEndpoint" : "usingSSM"));

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
                    equalTo(List.of("P2", "PCL200")));
            assertThat(
                    signedJWTResponse.getJWTClaimsSet().getClaim("reprove_identity"),
                    equalTo(true));
            assertThat(
                    signedJWTResponse.getHeader().getKeyID(),
                    equalTo(hashSha256String(IPV_SIGNING_KEY_ID)));
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
