package uk.gov.di.authentication.frontendapi.services;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.OIDCClaimsRequest;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSetRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedConstruction;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.shared.entity.ResponseHeaders;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.helpers.IdGenerator;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.RedisConnectionService;
import uk.gov.di.authentication.shared.services.SerializationService;
import uk.gov.di.authentication.shared.services.TokenService;
import uk.gov.di.authentication.sharedtest.helper.TestClockHelper;

import java.net.URI;
import java.net.URISyntaxException;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.REVERIFY_AUTHORISATION_REQUESTED;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.INTERNAL_SUBJECT_ID;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.SESSION_ID;

class MfaResetIPVAuthorizationServiceTest {
    private static final JWSAlgorithm TEST_SIGNING_ALGORITHM = JWSAlgorithm.ES256;
    private static final String TEST_MFA_RESET_SCOPE = "reverification";
    private static final String TEST_STATE_STORAGE_PREFIX = "state:";
    private static final String TEST_STATE_VALUE = "testState";
    private static final Session TEST_SESSION = new Session(SESSION_ID);
    private static final String TEST_CLIENT_SESSION_ID = "journeyId";
    private static final Subject TEST_SUBJECT = new Subject(INTERNAL_SUBJECT_ID);
    private static final String TEST_AUDIENCE_CLAIM = "someAud";
    private static final String TEST_ISSUER_CLAIM = "someIssuer";
    private static final String TEST_UUID = "someSuperUniqueUUID";
    private static final String TEST_IPV_AUTHORIZE_URI = "https://some.uri.gov.uk/authorize";
    private static final String TEST_IPV_AUTH_CLIENT_ID = "someClientId";
    private static final String TEST_KEY_ALIAS = "someKeyAlias";
    private static final String TEST_STORAGE_TOKEN =
            "eyJraWQiOiIxZDUwNGFlY2UyOThhMTRkNzRlZTBhMDJiNjc0MGI0MzcyYTFmYWI0MjA2Nzc4ZTQ4NmJhNzI3NzBmZjRiZWI4IiwiYWxnIjoiRVMyNTYifQ.eyJhdWQiOlsiaHR0cHM6Ly9jcmVkZW50aWFsLXN0b3JlLmFjY291bnQuZ292LnVrIiwiaHR0cHM6Ly9pZGVudGl0eS50ZXN0LmFjY291bnQuZ292LnVrIl0sInN1YiI6InVybjpmZGM6Z292LnVrOjIwMjI6VEpMdDNXYWlHa0xoOFVxZWlzSDJ6VktHQVAwIiwic2NvcGUiOiJwcm92aW5nIiwiaXNzIjoiaHR0cHM6Ly9vaWRjLnRlc3QuYWNjb3VudC5nb3YudWsiLCJleHAiOjE3MTgxOTU3NjMsImlhdCI6MTcxODE5NTQ2MywianRpIjoiMWQyZTdmODgtYWIwNy00NWU5LThkYTAtOWEyMzIyMWFhZjM3In0.6MpC8IZbOICVjvf_97ySj6yOO6khQGhkEGHvYB6kXGMroSQgF0z0-Z1EVJi5sVXwmbe4X6eDRTIYtM07xItiMg";
    private static final String TEST_STORAGE_TOKEN_CLAIM =
            "https://vocab.account.gov.uk/v1/storageAccessToken";
    private static final long TEST_SESSION_EXPIRY = 123456;
    private static final String TEST_MFA_CALLBACK_URI = "some.call.back.uri";
    private static final Base64URL TEST_ENCODED_JWS_HEADER =
            new JWSHeader(TEST_SIGNING_ALGORITHM).toBase64URL();
    private static final Base64URL TEST_ENCODED_JWS_SIGNATURE =
            new Base64URL("someVeryLegitSignature");
    private static final Base64URL TEST_JWE_FIRST_PART =
            new Base64URL("ewogICAgImFsZyI6ICJoZWxsbyIsCiAgICAiZW5jIjogIlRoZXJlIgp9");
    private static final Base64URL TEST_JWE_SECOND_PART = new Base64URL("someJWEEncryptionKey");
    private static final Base64URL TEST_JWE_THIRD_PART =
            new Base64URL("someJWEInitialisationVector");
    private static final Base64URL TEST_JWE_FOURTH_PART =
            new Base64URL("someJWESuperSecretCipherText");
    private static final Base64URL TEST_JWE_FIFTH_PART = new Base64URL("someJWEAuthenticationTag");
    private static final String TEST_PUBLIC_KEY = createTestRSAPublicKey();

    private final Json objectMapper = SerializationService.getInstance();
    private final JwtService jwtService = mock(JwtService.class);
    private final NowHelper.NowClock nowClock = TestClockHelper.getInstance();
    private final TokenService tokenService = mock(TokenService.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final RedisConnectionService redisConnectionService =
            mock(RedisConnectionService.class);
    private final AuditService auditService = mock(AuditService.class);
    private final AuditContext auditContext = mock(AuditContext.class);
    private final CloudwatchMetricsService cloudwatchMetricsService =
            mock(CloudwatchMetricsService.class);
    private final JWTClaimsSet TEST_JWT_CLAIMS = constructTestClaimSet();
    private final MfaResetIPVAuthorizationService mfaResetIPVAuthorizationService =
            new MfaResetIPVAuthorizationService(
                    configurationService,
                    nowClock,
                    jwtService,
                    tokenService,
                    redisConnectionService,
                    auditService,
                    cloudwatchMetricsService);
    private SignedJWT TEST_SIGNED_JWT;
    private EncryptedJWT TEST_ENCRYPTED_JWT;

    @BeforeEach
    void testSetup() throws URISyntaxException, ParseException {
        when(tokenService.generateStorageTokenForMfaReset(any()))
                .thenReturn(new BearerAccessToken(TEST_STORAGE_TOKEN));
        when(configurationService.getMfaResetJarSigningKeyAlias()).thenReturn(TEST_KEY_ALIAS);
        when(configurationService.getStorageTokenClaimName()).thenReturn(TEST_STORAGE_TOKEN_CLAIM);
        when(configurationService.getMfaResetCallbackURI())
                .thenReturn(new URI(TEST_MFA_CALLBACK_URI));
        when(configurationService.getIPVAuthEncryptionPublicKey()).thenReturn(TEST_PUBLIC_KEY);
        when(configurationService.getIPVAuthorisationClientId())
                .thenReturn(TEST_IPV_AUTH_CLIENT_ID);
        when(configurationService.getAuthIssuerClaim()).thenReturn(TEST_ISSUER_CLAIM);
        when(configurationService.getIPVAuthorisationURI())
                .thenReturn(new URI(TEST_IPV_AUTHORIZE_URI));
        when(configurationService.getSessionExpiry()).thenReturn(TEST_SESSION_EXPIRY);
        when(configurationService.getIPVAudience()).thenReturn(TEST_AUDIENCE_CLAIM);
        TEST_SIGNED_JWT =
                new SignedJWT(
                        TEST_ENCODED_JWS_HEADER,
                        Base64URL.encode(TEST_JWT_CLAIMS.toString()),
                        TEST_ENCODED_JWS_SIGNATURE);
        TEST_ENCRYPTED_JWT =
                new EncryptedJWT(
                        TEST_JWE_FIRST_PART,
                        TEST_JWE_SECOND_PART,
                        TEST_JWE_THIRD_PART,
                        TEST_JWE_FOURTH_PART,
                        TEST_JWE_FIFTH_PART);
        when(jwtService.signJWT(any(), any(), any())).thenReturn(TEST_SIGNED_JWT);
        when(jwtService.encryptJWT(any(), any())).thenReturn(TEST_ENCRYPTED_JWT);
        MockedStatic<IdGenerator> mockIdGen = Mockito.mockStatic(IdGenerator.class);
        mockIdGen.when(IdGenerator::generate).thenReturn(TEST_UUID);
    }

    @Test
    void shouldReturn302WithEncryptedJWT() throws JOSEException, Json.JsonException {
        try (MockedConstruction<State> mockedState =
                Mockito.mockConstruction(
                        State.class,
                        (mock, context) -> {
                            when(mock.getValue()).thenReturn(TEST_STATE_VALUE);
                        })) {
            APIGatewayProxyResponseEvent ipvRedirectResponse =
                    mfaResetIPVAuthorizationService.sendMfaResetRequestToIPV(
                            TEST_SUBJECT, TEST_CLIENT_SESSION_ID, TEST_SESSION, auditContext);
            String redirectURI = ipvRedirectResponse.getHeaders().get(ResponseHeaders.LOCATION);
            RSAPublicKey expectedPublicKey =
                    new RSAKey.Builder((RSAKey) JWK.parseFromPEMEncodedObjects(TEST_PUBLIC_KEY))
                            .build()
                            .toRSAPublicKey();
            verify(jwtService)
                    .signJWT(TEST_SIGNING_ALGORITHM, constructTestClaimSet(), TEST_KEY_ALIAS);
            verify(jwtService).encryptJWT(TEST_SIGNED_JWT, expectedPublicKey);
            verify(redisConnectionService)
                    .saveWithExpiry(
                            TEST_STATE_STORAGE_PREFIX + SESSION_ID,
                            objectMapper.writeValueAsString(TEST_STATE_VALUE),
                            TEST_SESSION_EXPIRY);
            verify(tokenService).generateStorageTokenForMfaReset(TEST_SUBJECT);
            assertEquals(302, ipvRedirectResponse.getStatusCode());
            assertEquals("", ipvRedirectResponse.getBody());
            assertEquals(
                    TEST_IPV_AUTHORIZE_URI
                            + "?response_type=code"
                            + "&request="
                            + TEST_ENCRYPTED_JWT.serialize()
                            + "&client_id="
                            + TEST_IPV_AUTH_CLIENT_ID,
                    redirectURI);
            verify(configurationService).getMfaResetJarSigningKeyAlias();
            verify(configurationService).getStorageTokenClaimName();
            verify(configurationService).getMfaResetCallbackURI();
            verify(configurationService).getIPVAuthEncryptionPublicKey();
            verify(configurationService, times(2)).getIPVAuthorisationClientId();
            verify(configurationService).getAuthIssuerClaim();
            verify(configurationService).getIPVAuthorisationURI();
            verify(configurationService).getSessionExpiry();
            verify(configurationService).getIPVAudience();
            verify(auditService).submitAuditEvent(REVERIFY_AUTHORISATION_REQUESTED, auditContext);
        }
    }

    private JWTClaimsSet constructTestClaimSet() {
        var claimsRequest =
                new OIDCClaimsRequest()
                        .withUserInfoClaimsRequest(
                                new ClaimsSetRequest()
                                        .add(
                                                new ClaimsSetRequest.Entry(TEST_STORAGE_TOKEN_CLAIM)
                                                        .withValues(List.of(TEST_STORAGE_TOKEN))));
        var claimsBuilder =
                new JWTClaimsSet.Builder()
                        .issuer(TEST_ISSUER_CLAIM)
                        .audience(TEST_AUDIENCE_CLAIM)
                        .expirationTime(
                                TestClockHelper.getInstance().nowPlus(3, ChronoUnit.MINUTES))
                        .subject(TEST_SUBJECT.getValue())
                        .issueTime(TestClockHelper.getInstance().now())
                        .jwtID(TEST_UUID)
                        .notBeforeTime(TestClockHelper.getInstance().now())
                        .claim("state", TEST_STATE_VALUE)
                        .claim("govuk_signin_journey_id", TEST_CLIENT_SESSION_ID)
                        .claim("redirect_uri", TEST_MFA_CALLBACK_URI)
                        .claim("client_id", TEST_IPV_AUTH_CLIENT_ID)
                        .claim("response_type", ResponseType.CODE.toString())
                        .claim("scope", TEST_MFA_RESET_SCOPE)
                        .claim("claims", claimsRequest.toJSONObject());
        return claimsBuilder.build();
    }

    private static String createTestRSAPublicKey() {
        KeyPairGenerator kpg;
        try {
            kpg = KeyPairGenerator.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        kpg.initialize(2048);
        var encodedKey =
                Base64.getMimeEncoder()
                        .encodeToString(kpg.generateKeyPair().getPublic().getEncoded());
        return "-----BEGIN PUBLIC KEY-----\n" + encodedKey + "\n-----END PUBLIC KEY-----\n";
    }
}
