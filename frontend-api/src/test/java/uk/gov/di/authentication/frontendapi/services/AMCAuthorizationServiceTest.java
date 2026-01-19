package uk.gov.di.authentication.frontendapi.services;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.impl.ECDSA;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.core.exception.SdkException;
import software.amazon.awssdk.services.kms.model.SignRequest;
import software.amazon.awssdk.services.kms.model.SignResponse;
import uk.gov.di.authentication.frontendapi.entity.AMCAuthorizeFailureReason;
import uk.gov.di.authentication.frontendapi.entity.AMCScope;
import uk.gov.di.authentication.frontendapi.exceptions.JwtServiceException;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.KmsConnectionService;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.sharedtest.helper.KeyPairHelper.GENERATE_RSA_KEY_PAIR;

class AMCAuthorizationServiceTest {
    private AMCAuthorizationService amcAuthorizationService;
    private static final String INTERNAL_PAIRWISE_ID =
            "urn:fdc:gov.uk:2022:xH7hrtJCgdi2NEF7TXcOC6SMz8DohdoLo9hWqQMWPRk";
    private static final String AUTH_ISSUER_CLAIM = "https://signin.account.gov.uk/";
    private static final String AUTH_TO_AUTH_AUDIENCE = "https://api.manage.account.gov.uk";
    private static final String AUTH_TO_AMC_AUDIENCE = "https://amc.account.gov.uk";
    private static final String CLIENT_ID = "test-client-id";
    private static final String SESSION_ID = "test-session-id";
    private static final String RESPONSE_TYPE = "code";
    private static final String REDIRECT_URI = "https://example.com/callback";
    private static final String AMC_CLIENT_ID = "amc-client-id";
    private static final String AMC_AUTHORIZE_URI = "https://amc.account.gov.uk/authorize";
    private static final String EMAIL = "test@example.com";
    private static final String JOURNEY_ID = "test-journey-id";
    private static final String PUBLIC_SUBJECT = "test-public-subject";
    private static final String ACCESS_TOKEN_KEY_ALIAS = "test-key-alias";
    private static final String COMPOSITE_JWT_KEY_ALIAS = "auth-to-amc-test-key-alias";
    private static final KeyPair TEST_KEY_PAIR = GENERATE_RSA_KEY_PAIR();
    private static final RSAPublicKey TEST_PUBLIC_KEY = (RSAPublicKey) TEST_KEY_PAIR.getPublic();
    private static final RSAPrivateKey TEST_PRIVATE_KEY =
            (RSAPrivateKey) TEST_KEY_PAIR.getPrivate();
    private static final AuthSessionItem authSessionItem = mock(AuthSessionItem.class);

    // Ensure 0 milliseconds for JWT compatibility
    private static final Date NOW =
            Date.from(
                    Instant.now().plus(20 * 365, ChronoUnit.DAYS).truncatedTo(ChronoUnit.SECONDS));
    private static final long SESSION_EXPIRY = 300L;

    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final NowHelper.NowClock nowClock = mock(NowHelper.NowClock.class);
    private final KmsConnectionService kmsConnectionService = mock(KmsConnectionService.class);

    @BeforeEach
    void setup() {
        JwtService jwtService = new JwtService(kmsConnectionService);
        amcAuthorizationService =
                new AMCAuthorizationService(configurationService, nowClock, jwtService);
    }

    @Test
    void shouldBuildAuthorizationUrlWithValidJWT() throws Exception {
        ECKey accessTokenKey =
                new ECKeyGenerator(Curve.P_256).algorithm(JWSAlgorithm.ES256).generate();
        ECKey compositeJWTKey =
                new ECKeyGenerator(Curve.P_256).algorithm(JWSAlgorithm.ES256).generate();
        when(configurationService.getAuthToAMCPublicEncryptionKey())
                .thenReturn(constructTestPublicKey());
        Date expiryDate = new Date(NOW.getTime() + (SESSION_EXPIRY * 1000));
        mockConfigurationService(expiryDate);
        mockAuthSessionItem();
        mockKmsSigningWithDifferentKeys(accessTokenKey, compositeJWTKey);
        when(authSessionItem.getEmailAddress()).thenReturn(EMAIL);

        Result<AMCAuthorizeFailureReason, String> result =
                amcAuthorizationService.buildAuthorizationUrl(
                        new Subject(INTERNAL_PAIRWISE_ID),
                        new AMCScope[] {AMCScope.ACCOUNT_DELETE},
                        authSessionItem,
                        JOURNEY_ID,
                        PUBLIC_SUBJECT);

        assertTrue(result.isSuccess());
        String authorizationUrl = result.getSuccess();
        assertTrue(authorizationUrl.startsWith(AMC_AUTHORIZE_URI));

        AuthorizationRequest authRequest = AuthorizationRequest.parse(authorizationUrl);
        EncryptedJWT encryptedJWT = (EncryptedJWT) authRequest.getRequestObject();
        encryptedJWT.decrypt(new RSADecrypter(TEST_PRIVATE_KEY));
        SignedJWT compositeJWT = encryptedJWT.getPayload().toSignedJWT();

        assertTrue(compositeJWT.verify(new ECDSAVerifier(compositeJWTKey.toECPublicKey())));

        JWTClaimsSet compositeClaims = compositeJWT.getJWTClaimsSet();
        assertCompositeJWTClaims(compositeClaims, expiryDate);

        var accessTokenValue = (String) compositeClaims.getClaim("access_token");
        SignedJWT accessTokenJWT = SignedJWT.parse(accessTokenValue);
        assertTrue(accessTokenJWT.verify(new ECDSAVerifier(accessTokenKey.toECPublicKey())));

        JWTClaimsSet accessTokenClaims = accessTokenJWT.getJWTClaimsSet();
        assertAccessTokenClaims(accessTokenClaims, expiryDate);
    }

    @Test
    void shouldReturnFailureWhenKmsSigningFails() {
        Date expiryDate = new Date(NOW.getTime() + (SESSION_EXPIRY * 1000));
        mockConfigurationService(expiryDate);
        mockAuthSessionItem();
        when(authSessionItem.getEmailAddress()).thenReturn(EMAIL);

        when(kmsConnectionService.sign(any(SignRequest.class)))
                .thenThrow(SdkException.builder().message("KMS Unreachable").build());

        Result<AMCAuthorizeFailureReason, String> result =
                amcAuthorizationService.buildAuthorizationUrl(
                        new Subject(INTERNAL_PAIRWISE_ID),
                        new AMCScope[] {AMCScope.ACCOUNT_DELETE},
                        authSessionItem,
                        JOURNEY_ID,
                        PUBLIC_SUBJECT);

        assertTrue(result.isFailure());
        assertEquals(AMCAuthorizeFailureReason.SIGNING_ERROR, result.getFailure());
    }

    @Test
    void shouldReturnFailureWhenSignatureTranscodingFails() {
        Date expiryDate = new Date(NOW.getTime() + (SESSION_EXPIRY * 1000));
        mockConfigurationService(expiryDate);
        mockAuthSessionItem();
        when(authSessionItem.getEmailAddress()).thenReturn(EMAIL);

        when(kmsConnectionService.sign(any(SignRequest.class)))
                .thenReturn(
                        SignResponse.builder()
                                .signature(SdkBytes.fromByteArray(new byte[] {0x00, 0x01}))
                                .build());

        Result<AMCAuthorizeFailureReason, String> result =
                amcAuthorizationService.buildAuthorizationUrl(
                        new Subject(INTERNAL_PAIRWISE_ID),
                        new AMCScope[] {AMCScope.ACCOUNT_DELETE},
                        authSessionItem,
                        JOURNEY_ID,
                        PUBLIC_SUBJECT);

        assertTrue(result.isFailure());
        assertEquals(AMCAuthorizeFailureReason.TRANSCODING_ERROR, result.getFailure());
    }

    @Test
    void shouldReturnJwtConstructionErrorForUnknownExceptionCause() {
        Date expiryDate = new Date(NOW.getTime() + (SESSION_EXPIRY * 1000));
        mockConfigurationService(expiryDate);
        mockAuthSessionItem();
        when(authSessionItem.getEmailAddress()).thenReturn(EMAIL);

        JwtService mockJwtService = mock(JwtService.class);
        when(mockJwtService.signJWT(any(), any()))
                .thenThrow(new JwtServiceException("Unknown error"));

        AMCAuthorizationService serviceWithMockJwt =
                new AMCAuthorizationService(configurationService, nowClock, mockJwtService);

        Result<AMCAuthorizeFailureReason, String> result =
                serviceWithMockJwt.buildAuthorizationUrl(
                        new Subject(INTERNAL_PAIRWISE_ID),
                        new AMCScope[] {AMCScope.ACCOUNT_DELETE},
                        authSessionItem,
                        JOURNEY_ID,
                        PUBLIC_SUBJECT);

        assertTrue(result.isFailure());
        assertEquals(AMCAuthorizeFailureReason.UNKNOWN_JWT_SIGNING_ERROR, result.getFailure());
    }

    @Test
    void shouldHandleMultipleScopes() throws Exception {
        ECKey accessTokenKey =
                new ECKeyGenerator(Curve.P_256).algorithm(JWSAlgorithm.ES256).generate();
        ECKey compositeJWTKey =
                new ECKeyGenerator(Curve.P_256).algorithm(JWSAlgorithm.ES256).generate();
        when(configurationService.getAuthToAMCPublicEncryptionKey())
                .thenReturn(constructTestPublicKey());
        Date expiryDate = new Date(NOW.getTime() + (SESSION_EXPIRY * 1000));
        mockConfigurationService(expiryDate);
        mockAuthSessionItem();
        mockKmsSigningWithDifferentKeys(accessTokenKey, compositeJWTKey);
        when(authSessionItem.getEmailAddress()).thenReturn(EMAIL);

        Result<AMCAuthorizeFailureReason, String> result =
                amcAuthorizationService.buildAuthorizationUrl(
                        new Subject(INTERNAL_PAIRWISE_ID),
                        new AMCScope[] {AMCScope.ACCOUNT_DELETE, AMCScope.ACCOUNT_DELETE},
                        authSessionItem,
                        JOURNEY_ID,
                        PUBLIC_SUBJECT);

        assertTrue(result.isSuccess());
        AuthorizationRequest authRequest = AuthorizationRequest.parse(result.getSuccess());
        EncryptedJWT encryptedJWT = (EncryptedJWT) authRequest.getRequestObject();
        encryptedJWT.decrypt(new RSADecrypter(TEST_PRIVATE_KEY));
        SignedJWT compositeJWT = encryptedJWT.getPayload().toSignedJWT();
        JWTClaimsSet compositeClaims = compositeJWT.getJWTClaimsSet();

        assertEquals(
                List.of(AMCScope.ACCOUNT_DELETE.getValue(), AMCScope.ACCOUNT_DELETE.getValue()),
                compositeClaims.getClaim("scope"));
    }

    @Test
    void shouldReturnJwtEncodingErrorWhenParseExceptionOccurs() {
        Date expiryDate = new Date(NOW.getTime() + (SESSION_EXPIRY * 1000));
        mockConfigurationService(expiryDate);
        mockAuthSessionItem();
        when(authSessionItem.getEmailAddress()).thenReturn(EMAIL);

        JwtService mockJwtService = mock(JwtService.class);
        when(mockJwtService.signJWT(any(), any()))
                .thenThrow(
                        new JwtServiceException(
                                "Parse error", new java.text.ParseException("Invalid", 0)));

        AMCAuthorizationService serviceWithMockJwt =
                new AMCAuthorizationService(configurationService, nowClock, mockJwtService);

        Result<AMCAuthorizeFailureReason, String> result =
                serviceWithMockJwt.buildAuthorizationUrl(
                        new Subject(INTERNAL_PAIRWISE_ID),
                        new AMCScope[] {AMCScope.ACCOUNT_DELETE},
                        authSessionItem,
                        JOURNEY_ID,
                        PUBLIC_SUBJECT);

        assertTrue(result.isFailure());
        assertEquals(AMCAuthorizeFailureReason.JWT_ENCODING_ERROR, result.getFailure());
    }

    @Test
    void shouldReturnJwtEncodingErrorWhenPublicKeyParsingFails() throws Exception {
        ECKey accessTokenKey =
                new ECKeyGenerator(Curve.P_256).algorithm(JWSAlgorithm.ES256).generate();
        ECKey compositeJWTKey =
                new ECKeyGenerator(Curve.P_256).algorithm(JWSAlgorithm.ES256).generate();
        when(configurationService.getAuthToAMCPublicEncryptionKey()).thenReturn("invalid-pem-key");
        Date expiryDate = new Date(NOW.getTime() + (SESSION_EXPIRY * 1000));
        mockConfigurationService(expiryDate);
        mockAuthSessionItem();
        mockKmsSigningWithDifferentKeys(accessTokenKey, compositeJWTKey);
        when(authSessionItem.getEmailAddress()).thenReturn(EMAIL);

        Result<AMCAuthorizeFailureReason, String> result =
                amcAuthorizationService.buildAuthorizationUrl(
                        new Subject(INTERNAL_PAIRWISE_ID),
                        new AMCScope[] {AMCScope.ACCOUNT_DELETE},
                        authSessionItem,
                        JOURNEY_ID,
                        PUBLIC_SUBJECT);

        assertTrue(result.isFailure());
        assertEquals(AMCAuthorizeFailureReason.JWT_ENCODING_ERROR, result.getFailure());
    }

    private void mockKmsSigningWithDifferentKeys(ECKey accessTokenKey, ECKey compositeJWTKey) {
        when(kmsConnectionService.sign(any(SignRequest.class)))
                .thenAnswer(
                        invocation -> {
                            SignRequest request = invocation.getArgument(0);
                            String keyId = request.keyId();
                            String input = request.message().asUtf8String();

                            ECKey keyToUse =
                                    keyId.equals(ACCESS_TOKEN_KEY_ALIAS)
                                            ? accessTokenKey
                                            : compositeJWTKey;

                            byte[] signature =
                                    new ECDSASigner(keyToUse)
                                            .sign(
                                                    new JWSHeader(JWSAlgorithm.ES256),
                                                    input.getBytes(StandardCharsets.UTF_8))
                                            .decode();

                            byte[] derSignature = ECDSA.transcodeSignatureToDER(signature);

                            return SignResponse.builder()
                                    .signature(SdkBytes.fromByteArray(derSignature))
                                    .build();
                        });
    }

    private void mockConfigurationService(Date expiryDate) {
        when(configurationService.getAuthIssuerClaim()).thenReturn(AUTH_ISSUER_CLAIM);
        when(configurationService.getAuthToAuthAudience()).thenReturn(AUTH_TO_AUTH_AUDIENCE);
        when(configurationService.getAuthToAMCAudience()).thenReturn(AUTH_TO_AMC_AUDIENCE);
        when(configurationService.getSessionExpiry()).thenReturn(SESSION_EXPIRY);
        when(configurationService.getAuthToAccountManagementPrivateSigningKeyAlias())
                .thenReturn(ACCESS_TOKEN_KEY_ALIAS);
        when(configurationService.getAuthToAMCPrivateSigningKeyAlias())
                .thenReturn(COMPOSITE_JWT_KEY_ALIAS);
        when(configurationService.getAMCRedirectURI()).thenReturn(REDIRECT_URI);
        when(configurationService.getAMCClientId()).thenReturn(AMC_CLIENT_ID);
        when(configurationService.getAMCAuthorizeURI()).thenReturn(URI.create(AMC_AUTHORIZE_URI));
        when(nowClock.now()).thenReturn(NOW);
        when(nowClock.nowPlus(SESSION_EXPIRY, ChronoUnit.SECONDS)).thenReturn(expiryDate);
    }

    private void mockAuthSessionItem() {
        when(authSessionItem.getClientId()).thenReturn(CLIENT_ID);
        when(authSessionItem.getSessionId()).thenReturn(SESSION_ID);
    }

    private void assertCompositeJWTClaims(JWTClaimsSet compositeClaims, Date expiryDate) {
        assertAll(
                "Composite JWT Claims",
                () -> assertEquals(AUTH_ISSUER_CLAIM, compositeClaims.getIssuer()),
                () -> assertEquals(List.of(AUTH_TO_AMC_AUDIENCE), compositeClaims.getAudience()),
                () -> assertEquals(CLIENT_ID, compositeClaims.getClaim("client_id")),
                () -> assertEquals(RESPONSE_TYPE, compositeClaims.getClaim("response_type")),
                () -> assertEquals(REDIRECT_URI, compositeClaims.getClaim("redirect_uri")),
                () ->
                        assertEquals(
                                List.of(AMCScope.ACCOUNT_DELETE.getValue()),
                                compositeClaims.getClaim("scope")),
                () -> assertDoesNotThrow(() -> compositeClaims.getClaim("state")),
                () -> assertEquals(INTERNAL_PAIRWISE_ID, compositeClaims.getSubject()),
                () -> assertEquals(EMAIL, compositeClaims.getClaim("email")),
                () -> assertEquals(JOURNEY_ID, compositeClaims.getClaim("govuk_signin_journey_id")),
                () -> assertEquals(PUBLIC_SUBJECT, compositeClaims.getClaim("public_sub")),
                () -> assertEquals(NOW, compositeClaims.getIssueTime()),
                () -> assertEquals(NOW, compositeClaims.getNotBeforeTime()),
                () -> assertEquals(expiryDate, compositeClaims.getExpirationTime()),
                () -> assertDoesNotThrow(() -> UUID.fromString(compositeClaims.getJWTID())));
    }

    private void assertAccessTokenClaims(JWTClaimsSet accessTokenClaims, Date expiryDate) {
        assertAll(
                "Access Token Claims",
                () -> assertEquals(AUTH_ISSUER_CLAIM, accessTokenClaims.getIssuer()),
                () -> assertEquals(INTERNAL_PAIRWISE_ID, accessTokenClaims.getSubject()),
                () -> assertEquals(List.of(AUTH_TO_AUTH_AUDIENCE), accessTokenClaims.getAudience()),
                () ->
                        assertEquals(
                                List.of(AMCScope.ACCOUNT_DELETE.getValue()),
                                accessTokenClaims.getClaim("scope")),
                () -> assertEquals(CLIENT_ID, accessTokenClaims.getClaim("client_id")),
                () -> assertEquals(SESSION_ID, accessTokenClaims.getClaim("sid")),
                () -> assertEquals(NOW, accessTokenClaims.getIssueTime()),
                () -> assertEquals(NOW, accessTokenClaims.getNotBeforeTime()),
                () -> assertEquals(expiryDate, accessTokenClaims.getExpirationTime()),
                () -> assertDoesNotThrow(() -> UUID.fromString(accessTokenClaims.getJWTID())));
    }

    private static String constructTestPublicKey() {
        var encodedKey = Base64.getMimeEncoder().encodeToString(TEST_PUBLIC_KEY.getEncoded());
        return "-----BEGIN PUBLIC KEY-----\n" + encodedKey + "\n-----END PUBLIC KEY-----\n";
    }
}
