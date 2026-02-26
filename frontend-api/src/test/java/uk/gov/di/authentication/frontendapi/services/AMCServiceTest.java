package uk.gov.di.authentication.frontendapi.services;

import com.nimbusds.jose.JOSEException;
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
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.PrivateKeyJWT;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.core.exception.SdkException;
import software.amazon.awssdk.services.kms.model.KmsException;
import software.amazon.awssdk.services.kms.model.SignRequest;
import software.amazon.awssdk.services.kms.model.SignResponse;
import uk.gov.di.authentication.frontendapi.entity.amc.AMCScope;
import uk.gov.di.authentication.frontendapi.entity.amc.JourneyOutcomeError;
import uk.gov.di.authentication.frontendapi.entity.amc.JwtFailureReason;
import uk.gov.di.authentication.frontendapi.exceptions.JwtServiceException;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.KmsConnectionService;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.CLIENT_ID;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.EMAIL;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.SESSION_ID;
import static uk.gov.di.authentication.sharedtest.helper.KeyPairHelper.GENERATE_RSA_KEY_PAIR;

class AMCServiceTest {
    private AMCService amcService;
    private static final String INTERNAL_PAIRWISE_ID =
            "urn:fdc:gov.uk:2022:xH7hrtJCgdi2NEF7TXcOC6SMz8DohdoLo9hWqQMWPRk";
    private static final String AUTH_ISSUER_CLAIM = "https://signin.account.gov.uk/";
    private static final String AUTH_TO_AUTH_AUDIENCE = "https://api.manage.account.gov.uk";
    private static final String AUTH_TO_AMC_AUDIENCE = "https://amc.account.gov.uk";
    private static final String AUTH_TO_AMC_PRIVATE_AUDIENCE = "https://amc.account.gov.uk";
    private static final String RESPONSE_TYPE = "code";
    private static final String REDIRECT_URI = "https://example.com/callback";
    private static final String AMC_CLIENT_ID = "amc-client-id";
    private static final String AMC_AUTHORIZE_URI = "https://amc.account.gov.uk/authorize";
    private static final URI TOKEN_ENDPOINT_URI = URI.create("https://amc.account.gov.uk/token");
    private static final String JOURNEY_ID = "test-journey-id";
    private static final String PUBLIC_SUBJECT = "test-public-subject";
    private static final String ACCESS_TOKEN_KEY_ALIAS = "test-key-alias";
    private static final String COMPOSITE_JWT_KEY_ALIAS = "auth-to-amc-test-key-alias";
    private static final KeyPair TEST_KEY_PAIR = GENERATE_RSA_KEY_PAIR();
    private static final RSAPublicKey TEST_PUBLIC_KEY = (RSAPublicKey) TEST_KEY_PAIR.getPublic();
    private static final RSAPrivateKey TEST_PRIVATE_KEY =
            (RSAPrivateKey) TEST_KEY_PAIR.getPrivate();
    private AuthSessionItem authSessionItem;
    private static final String AUTH_CODE = "1234";

    // Ensure 0 milliseconds for JWT compatibility
    private static final Instant NOW_INSTANT = Instant.now().truncatedTo(ChronoUnit.SECONDS);
    private static final Date NOW = Date.from(NOW_INSTANT);
    private static final Long CLIENT_ASSERTION_LIFETIME = 5L;
    private static final Date JWT_EXPIRY =
            Date.from(NOW_INSTANT.plus(CLIENT_ASSERTION_LIFETIME, ChronoUnit.MINUTES));
    private static final NowHelper.NowClock NOW_CLOCK =
            new NowHelper.NowClock(Clock.fixed(NOW_INSTANT, ZoneOffset.UTC));

    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final KmsConnectionService kmsConnectionService = mock(KmsConnectionService.class);

    private final JwtService jwtService = new JwtService(kmsConnectionService);

    @BeforeEach
    void setup() {
        amcService = new AMCService(configurationService, NOW_CLOCK, jwtService);
        authSessionItem =
                new AuthSessionItem()
                        .withClientId(CLIENT_ID)
                        .withSessionId(SESSION_ID)
                        .withEmailAddress(EMAIL);
        mockConfigurationService();
    }

    private void mockConfigurationService() {
        when(configurationService.getAuthIssuerClaim()).thenReturn(AUTH_ISSUER_CLAIM);
        when(configurationService.getAuthToAMAPIAudience()).thenReturn(AUTH_TO_AUTH_AUDIENCE);
        when(configurationService.getAuthToAMCAudience()).thenReturn(AUTH_TO_AMC_AUDIENCE);
        when(configurationService.getAuthToAccountManagementPrivateSigningKeyAlias())
                .thenReturn(ACCESS_TOKEN_KEY_ALIAS);
        when(configurationService.getAuthToAMCPrivateSigningKeyAlias())
                .thenReturn(COMPOSITE_JWT_KEY_ALIAS);
        when(configurationService.getAMCRedirectURI()).thenReturn(REDIRECT_URI);
        when(configurationService.getAMCClientId()).thenReturn(AMC_CLIENT_ID);
        when(configurationService.getAMCAuthorizeURI()).thenReturn(URI.create(AMC_AUTHORIZE_URI));
    }

    @Nested
    class AuthorizationUrlTests {

        private final ECKey accessTokenKey =
                new ECKeyGenerator(Curve.P_256).algorithm(JWSAlgorithm.ES256).generate();
        private final ECKey compositeJWTKey =
                new ECKeyGenerator(Curve.P_256).algorithm(JWSAlgorithm.ES256).generate();

        AuthorizationUrlTests() throws JOSEException {}

        @Test
        void shouldBuildAuthorizationUrlWithValidJWT() throws Exception {
            when(configurationService.getAuthToAMCPublicEncryptionKey())
                    .thenReturn(constructTestPublicKey());
            mockKmsSigning(
                    Map.of(
                            ACCESS_TOKEN_KEY_ALIAS, accessTokenKey,
                            COMPOSITE_JWT_KEY_ALIAS, compositeJWTKey));

            Result<JwtFailureReason, String> result =
                    amcService.buildAuthorizationUrl(
                            INTERNAL_PAIRWISE_ID,
                            new AMCScope[] {AMCScope.ACCOUNT_DELETE},
                            authSessionItem,
                            JOURNEY_ID,
                            PUBLIC_SUBJECT);

            assertTrue(result.isSuccess());
            String authorizationUrl = result.getSuccess();
            assertTrue(authorizationUrl.startsWith(AMC_AUTHORIZE_URI));

            SignedJWT compositeJWT = extractSignedJwtFromAuthUrl(authorizationUrl);

            assertTrue(compositeJWT.verify(new ECDSAVerifier(compositeJWTKey.toECPublicKey())));

            JWTClaimsSet compositeClaims = compositeJWT.getJWTClaimsSet();
            assertCompositeJWTClaims(compositeClaims);

            var accessTokenValue = (String) compositeClaims.getClaim("access_token");
            SignedJWT accessTokenJWT = SignedJWT.parse(accessTokenValue);
            assertTrue(accessTokenJWT.verify(new ECDSAVerifier(accessTokenKey.toECPublicKey())));

            JWTClaimsSet accessTokenClaims = accessTokenJWT.getJWTClaimsSet();
            assertAccessTokenClaims(accessTokenClaims);
        }

        @Test
        void shouldHandleMultipleScopes() throws Exception {
            when(configurationService.getAuthToAMCPublicEncryptionKey())
                    .thenReturn(constructTestPublicKey());
            mockKmsSigning(
                    Map.of(
                            ACCESS_TOKEN_KEY_ALIAS, accessTokenKey,
                            COMPOSITE_JWT_KEY_ALIAS, compositeJWTKey));

            Result<JwtFailureReason, String> result =
                    amcService.buildAuthorizationUrl(
                            INTERNAL_PAIRWISE_ID,
                            new AMCScope[] {AMCScope.ACCOUNT_DELETE, AMCScope.ACCOUNT_DELETE},
                            authSessionItem,
                            JOURNEY_ID,
                            PUBLIC_SUBJECT);

            assertTrue(result.isSuccess());
            SignedJWT compositeJWT = extractSignedJwtFromAuthUrl(result.getSuccess());
            JWTClaimsSet compositeClaims = compositeJWT.getJWTClaimsSet();

            assertEquals(
                    List.of(AMCScope.ACCOUNT_DELETE.getValue(), AMCScope.ACCOUNT_DELETE.getValue()),
                    compositeClaims.getClaim("scope"));
        }

        @Test
        void shouldReturnFailureWhenKmsSigningFails() {
            when(kmsConnectionService.sign(any(SignRequest.class)))
                    .thenThrow(SdkException.builder().message("KMS Unreachable").build());

            Result<JwtFailureReason, String> result =
                    amcService.buildAuthorizationUrl(
                            INTERNAL_PAIRWISE_ID,
                            new AMCScope[] {AMCScope.ACCOUNT_DELETE},
                            authSessionItem,
                            JOURNEY_ID,
                            PUBLIC_SUBJECT);

            assertTrue(result.isFailure());
            assertEquals(JwtFailureReason.SIGNING_ERROR, result.getFailure());
        }

        @Test
        void shouldReturnFailureWhenSignatureTranscodingFails() {
            when(kmsConnectionService.sign(any(SignRequest.class)))
                    .thenReturn(
                            SignResponse.builder()
                                    .signature(SdkBytes.fromByteArray(new byte[] {0x00, 0x01}))
                                    .build());

            Result<JwtFailureReason, String> result =
                    amcService.buildAuthorizationUrl(
                            INTERNAL_PAIRWISE_ID,
                            new AMCScope[] {AMCScope.ACCOUNT_DELETE},
                            authSessionItem,
                            JOURNEY_ID,
                            PUBLIC_SUBJECT);

            assertTrue(result.isFailure());
            assertEquals(JwtFailureReason.TRANSCODING_ERROR, result.getFailure());
        }

        private static Stream<Arguments> jwtServiceErrorsToJwtFailureReason() {
            return Stream.of(
                    Arguments.of(
                            new JwtServiceException(
                                    "Encryption failed",
                                    new com.nimbusds.jose.JOSEException("Encryption error")),
                            JwtFailureReason.ENCRYPTION_ERROR),
                    Arguments.of(
                            new JwtServiceException("Unknown encryption error"),
                            JwtFailureReason.UNKNOWN_JWT_ENCRYPTING_ERROR),
                    Arguments.of(
                            new JwtServiceException(
                                    "Parse error", new java.text.ParseException("Invalid", 0)),
                            JwtFailureReason.JWT_ENCODING_ERROR));
        }

        @ParameterizedTest
        @MethodSource("jwtServiceErrorsToJwtFailureReason")
        void shouldMapJwtServiceExceptionsToJwtFailureReason(
                Exception encryptionException, JwtFailureReason expectedFailureReason)
                throws JOSEException {
            when(configurationService.getAuthToAMCPublicEncryptionKey())
                    .thenReturn(constructTestPublicKey());

            JwtService mockJwtService = mock(JwtService.class);
            SignedJWT signedJWT =
                    new SignedJWT(
                            new JWSHeader(JWSAlgorithm.ES256), new JWTClaimsSet.Builder().build());
            signedJWT.sign(new ECDSASigner(accessTokenKey));
            when(mockJwtService.signJWT(any(), any())).thenReturn(signedJWT);
            when(mockJwtService.encryptJWT(any(), any())).thenThrow(encryptionException);

            AMCService serviceWithMockJwt =
                    new AMCService(configurationService, NOW_CLOCK, mockJwtService);

            Result<JwtFailureReason, String> result =
                    serviceWithMockJwt.buildAuthorizationUrl(
                            INTERNAL_PAIRWISE_ID,
                            new AMCScope[] {AMCScope.ACCOUNT_DELETE},
                            authSessionItem,
                            JOURNEY_ID,
                            PUBLIC_SUBJECT);

            assertTrue(result.isFailure());
            assertEquals(expectedFailureReason, result.getFailure());
        }

        @Test
        void shouldReturnJwtConstructionErrorForUnknownExceptionCause() {
            JwtService mockJwtService = mock(JwtService.class);
            when(mockJwtService.signJWT(any(), any()))
                    .thenThrow(new JwtServiceException("Unknown error"));

            AMCService serviceWithMockJwt =
                    new AMCService(configurationService, NOW_CLOCK, mockJwtService);

            Result<JwtFailureReason, String> result =
                    serviceWithMockJwt.buildAuthorizationUrl(
                            INTERNAL_PAIRWISE_ID,
                            new AMCScope[] {AMCScope.ACCOUNT_DELETE},
                            authSessionItem,
                            JOURNEY_ID,
                            PUBLIC_SUBJECT);

            assertTrue(result.isFailure());
            assertEquals(JwtFailureReason.UNKNOWN_JWT_SIGNING_ERROR, result.getFailure());
        }

        @Test
        void shouldReturnJwtEncodingErrorWhenParseExceptionOccurs() {
            JwtService mockJwtService = mock(JwtService.class);
            when(mockJwtService.signJWT(any(), any()))
                    .thenThrow(
                            new JwtServiceException(
                                    "Parse error", new java.text.ParseException("Invalid", 0)));

            AMCService serviceWithMockJwt =
                    new AMCService(configurationService, NOW_CLOCK, mockJwtService);

            Result<JwtFailureReason, String> result =
                    serviceWithMockJwt.buildAuthorizationUrl(
                            INTERNAL_PAIRWISE_ID,
                            new AMCScope[] {AMCScope.ACCOUNT_DELETE},
                            authSessionItem,
                            JOURNEY_ID,
                            PUBLIC_SUBJECT);

            assertTrue(result.isFailure());
            assertEquals(JwtFailureReason.JWT_ENCODING_ERROR, result.getFailure());
        }

        @Test
        void shouldReturnJwtEncodingErrorWhenPublicKeyParsingFails() throws Exception {
            when(configurationService.getAuthToAMCPublicEncryptionKey())
                    .thenReturn("invalid-pem-key");
            mockKmsSigning(
                    Map.of(
                            ACCESS_TOKEN_KEY_ALIAS, accessTokenKey,
                            COMPOSITE_JWT_KEY_ALIAS, compositeJWTKey));

            Result<JwtFailureReason, String> result =
                    amcService.buildAuthorizationUrl(
                            INTERNAL_PAIRWISE_ID,
                            new AMCScope[] {AMCScope.ACCOUNT_DELETE},
                            authSessionItem,
                            JOURNEY_ID,
                            PUBLIC_SUBJECT);

            assertTrue(result.isFailure());
            assertEquals(JwtFailureReason.JWT_ENCODING_ERROR, result.getFailure());
        }

        private void assertCompositeJWTClaims(JWTClaimsSet compositeClaims) {
            assertAll(
                    "Composite JWT Claims",
                    () -> assertEquals(AUTH_ISSUER_CLAIM, compositeClaims.getIssuer()),
                    () ->
                            assertEquals(
                                    List.of(AUTH_TO_AMC_AUDIENCE), compositeClaims.getAudience()),
                    () -> assertEquals(AMC_CLIENT_ID, compositeClaims.getClaim("client_id")),
                    () -> assertEquals(RESPONSE_TYPE, compositeClaims.getClaim("response_type")),
                    () -> assertEquals(REDIRECT_URI, compositeClaims.getClaim("redirect_uri")),
                    () ->
                            assertEquals(
                                    List.of(AMCScope.ACCOUNT_DELETE.getValue()),
                                    compositeClaims.getClaim("scope")),
                    () -> assertDoesNotThrow(() -> compositeClaims.getClaim("state")),
                    () -> assertEquals(INTERNAL_PAIRWISE_ID, compositeClaims.getSubject()),
                    () -> assertEquals(EMAIL, compositeClaims.getClaim("email")),
                    () ->
                            assertEquals(
                                    JOURNEY_ID,
                                    compositeClaims.getClaim("govuk_signin_journey_id")),
                    () -> assertEquals(PUBLIC_SUBJECT, compositeClaims.getClaim("public_sub")),
                    () -> assertEquals(NOW.toInstant(), compositeClaims.getIssueTime().toInstant()),
                    () ->
                            assertEquals(
                                    NOW.toInstant(),
                                    compositeClaims.getNotBeforeTime().toInstant()),
                    () ->
                            assertEquals(
                                    JWT_EXPIRY.toInstant(),
                                    compositeClaims.getExpirationTime().toInstant()),
                    () -> assertDoesNotThrow(() -> UUID.fromString(compositeClaims.getJWTID())));
        }

        private void assertAccessTokenClaims(JWTClaimsSet accessTokenClaims) {
            assertAll(
                    "Access Token Claims",
                    () -> assertEquals(AUTH_ISSUER_CLAIM, accessTokenClaims.getIssuer()),
                    () -> assertEquals(INTERNAL_PAIRWISE_ID, accessTokenClaims.getSubject()),
                    () ->
                            assertEquals(
                                    List.of(AUTH_TO_AUTH_AUDIENCE),
                                    accessTokenClaims.getAudience()),
                    () ->
                            assertEquals(
                                    List.of(AMCScope.ACCOUNT_DELETE.getValue()),
                                    accessTokenClaims.getClaim("scope")),
                    () -> assertEquals(AMC_CLIENT_ID, accessTokenClaims.getClaim("client_id")),
                    () -> assertEquals(SESSION_ID, accessTokenClaims.getClaim("sid")),
                    () ->
                            assertEquals(
                                    NOW.toInstant(), accessTokenClaims.getIssueTime().toInstant()),
                    () ->
                            assertEquals(
                                    NOW.toInstant(),
                                    accessTokenClaims.getNotBeforeTime().toInstant()),
                    () ->
                            assertEquals(
                                    JWT_EXPIRY.toInstant(),
                                    accessTokenClaims.getExpirationTime().toInstant()),
                    () -> assertDoesNotThrow(() -> UUID.fromString(accessTokenClaims.getJWTID())));
        }

        private static String constructTestPublicKey() {
            var encodedKey = Base64.getMimeEncoder().encodeToString(TEST_PUBLIC_KEY.getEncoded());
            return "-----BEGIN PUBLIC KEY-----\n" + encodedKey + "\n-----END PUBLIC KEY-----\n";
        }

        private SignedJWT extractSignedJwtFromAuthUrl(String authorizationUrl) throws Exception {
            AuthorizationRequest authRequest = AuthorizationRequest.parse(authorizationUrl);
            EncryptedJWT encryptedJWT = (EncryptedJWT) authRequest.getRequestObject();
            encryptedJWT.decrypt(new RSADecrypter(TEST_PRIVATE_KEY));
            return encryptedJWT.getPayload().toSignedJWT();
        }
    }

    @Nested
    @DisplayName("Token Tests")
    class TokenTests {

        private ECKey signingKeyPair;

        @BeforeEach
        void setup() throws JOSEException {
            when(configurationService.getAMCClientId()).thenReturn(AMC_CLIENT_ID);
            when(configurationService.getAuthToAMCPrivateAudience())
                    .thenReturn(AUTH_TO_AMC_PRIVATE_AUDIENCE);
            when(configurationService.getAMCRedirectURI()).thenReturn(REDIRECT_URI);
            when(configurationService.getAMCTokenEndpointURI()).thenReturn(TOKEN_ENDPOINT_URI);
            signingKeyPair =
                    new ECKeyGenerator(Curve.P_256)
                            .algorithm(JWSAlgorithm.ES256)
                            .keyIDFromThumbprint(true)
                            .generate();
        }

        @Test
        void shouldBuildTokenRequest() throws ParseException, JOSEException {
            when(configurationService.getAuthToAMCPrivateSigningKeyAlias())
                    .thenReturn(signingKeyPair.getKeyID());

            mockKmsSigning(Map.of(signingKeyPair.getKeyID(), signingKeyPair));

            TokenRequest result = amcService.buildTokenRequest(AUTH_CODE).getSuccess();

            var authGrant = (AuthorizationCodeGrant) result.getAuthorizationGrant();
            assertEquals(AUTH_CODE, authGrant.getAuthorizationCode().toString());
            assertEquals(URI.create(REDIRECT_URI), authGrant.getRedirectionURI());

            assertEquals(TOKEN_ENDPOINT_URI, result.getEndpointURI());

            ClientAuthentication clientAuth = result.getClientAuthentication();
            PrivateKeyJWT privateKeyJWT = (PrivateKeyJWT) clientAuth;
            SignedJWT signedJWT = privateKeyJWT.getClientAssertion();

            assertTrue(signedJWT.verify(new ECDSAVerifier(signingKeyPair.toECPublicKey())));

            JWTClaimsSet claims = signedJWT.getJWTClaimsSet();

            assertEquals(AMC_CLIENT_ID, claims.getIssuer());
            assertEquals(AMC_CLIENT_ID, claims.getSubject());
            assertEquals(List.of(AUTH_TO_AMC_AUDIENCE), claims.getAudience());
            assertInstanceOf(String.class, claims.getJWTID());
            assertEquals(NOW.toInstant(), claims.getIssueTime().toInstant());
            assertEquals(NOW.toInstant(), claims.getNotBeforeTime().toInstant());
            assertEquals(JWT_EXPIRY.toInstant(), claims.getExpirationTime().toInstant());
        }

        @Test
        void shouldReturnTokenRequestErrorWhenSigningFails() {
            var invalidKeyAlias = "invalid-key-alias";
            when(configurationService.getAuthToAMCPrivateSigningKeyAlias())
                    .thenReturn(invalidKeyAlias);

            when(kmsConnectionService.sign(
                            argThat(request -> request.keyId().equals(invalidKeyAlias))))
                    .thenThrow(KmsException.create("Unable to sign", new RuntimeException()));

            Result<JwtFailureReason, TokenRequest> result = amcService.buildTokenRequest(AUTH_CODE);

            assertTrue(result.isFailure());
            assertEquals(JwtFailureReason.SIGNING_ERROR, result.getFailure());
        }
    }

    @Nested
    @DisplayName("Journey Outcome Tests")
    class JourneyOutcomeTests {
        @Test
        void shouldSendAJourneyOutcomeRequest() throws IOException {
            var userInfoRequest = mock(UserInfoRequest.class);
            var httpRequest = mock(HTTPRequest.class);
            when(userInfoRequest.toHTTPRequest()).thenReturn(httpRequest);
            var response = new HTTPResponse(200);
            when(httpRequest.send()).thenReturn(response);

            var result = amcService.requestJourneyOutcome(userInfoRequest);

            assertEquals(Result.success(response), result);
        }

        @Test
        void shouldReturnAnErrorForAnUnsuccessfulRequest() throws IOException {
            var userInfoRequest = mock(UserInfoRequest.class);
            var httpRequest = mock(HTTPRequest.class);
            when(userInfoRequest.toHTTPRequest()).thenReturn(httpRequest);
            var response = new HTTPResponse(400);
            when(httpRequest.send()).thenReturn(response);

            var result = amcService.requestJourneyOutcome(userInfoRequest);

            assertEquals(
                    Result.failure(JourneyOutcomeError.ERROR_RESPONSE_FROM_JOURNEY_OUTCOME),
                    result);
        }

        @Test
        void shouldReturnAnErrorForAnIOException() throws IOException {
            var userInfoRequest = mock(UserInfoRequest.class);
            var httpRequest = mock(HTTPRequest.class);
            when(userInfoRequest.toHTTPRequest()).thenReturn(httpRequest);
            when(httpRequest.send()).thenThrow(new IOException("Uh oh"));

            var result = amcService.requestJourneyOutcome(userInfoRequest);

            assertEquals(Result.failure(JourneyOutcomeError.IO_EXCEPTION), result);
        }
    }

    private void mockKmsSigning(Map<String, ECKey> keysByAlias) {
        when(kmsConnectionService.sign(any(SignRequest.class)))
                .thenAnswer(
                        invocation -> {
                            SignRequest request = invocation.getArgument(0);
                            String keyId = request.keyId();
                            String input = request.message().asUtf8String();

                            ECKey key = keysByAlias.get(keyId);
                            if (key == null) {
                                throw new IllegalArgumentException(
                                        "Unexpected key alias: " + keyId);
                            }

                            byte[] signature =
                                    new ECDSASigner(key)
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
}
