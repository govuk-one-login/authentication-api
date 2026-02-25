package uk.gov.di.authentication.frontendapi.services;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
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
import software.amazon.awssdk.core.exception.SdkException;
import software.amazon.awssdk.services.kms.model.KmsException;
import uk.gov.di.authentication.frontendapi.entity.amc.AMCScope;
import uk.gov.di.authentication.frontendapi.entity.amc.JourneyOutcomeError;
import uk.gov.di.authentication.frontendapi.entity.amc.JwtFailureReason;
import uk.gov.di.authentication.frontendapi.exceptions.JwtServiceException;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.io.IOException;
import java.net.URI;
import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.sharedtest.helper.KeyPairHelper.GENERATE_RSA_KEY_PAIR;

class AMCServiceTest {
    private AMCService amcService;
    private static final String INTERNAL_PAIRWISE_ID =
            "urn:fdc:gov.uk:2022:xH7hrtJCgdi2NEF7TXcOC6SMz8DohdoLo9hWqQMWPRk";
    private static final String AUTH_ISSUER_CLAIM = "https://signin.account.gov.uk/";
    private static final String AUTH_TO_AUTH_AUDIENCE = "https://api.manage.account.gov.uk";
    private static final String AUTH_TO_AMC_AUDIENCE = "https://amc.account.gov.uk";
    private static final String AUTH_TO_AMC_PRIVATE_AUDIENCE = "https://amc.account.gov.uk";
    private static final String CLIENT_ID = "test-client-id";
    private static final String SESSION_ID = "test-session-id";
    private static final String RESPONSE_TYPE = "code";
    private static final String REDIRECT_URI = "https://example.com/callback";
    private static final String AMC_CLIENT_ID = "amc-client-id";
    private static final String AMC_AUTHORIZE_URI = "https://amc.account.gov.uk/authorize";
    private static final URI TOKEN_ENDPOINT_URI = URI.create("https://amc.account.gov.uk/token");
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
    private static final String AUTH_CODE = "1234";

    // Ensure 0 milliseconds for JWT compatibility
    private static final Date NOW =
            Date.from(
                    Instant.now().plus(20 * 365, ChronoUnit.DAYS).truncatedTo(ChronoUnit.SECONDS));
    private static final long SESSION_EXPIRY = 300L;

    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final NowHelper.NowClock nowClock = mock(NowHelper.NowClock.class);
    private final JwtService jwtService = mock(JwtService.class);
    private ECKey accessTokenKey;
    private ECKey compositeJWTKey;

    @BeforeEach
    void setup() throws Exception {
        amcService = new AMCService(configurationService, nowClock, jwtService);
        accessTokenKey = new ECKeyGenerator(Curve.P_256).algorithm(JWSAlgorithm.ES256).generate();
        compositeJWTKey = new ECKeyGenerator(Curve.P_256).algorithm(JWSAlgorithm.ES256).generate();
        mockJwtSigning(
                Map.of(
                        ACCESS_TOKEN_KEY_ALIAS, accessTokenKey,
                        COMPOSITE_JWT_KEY_ALIAS, compositeJWTKey));
        mockJwtEncryption();
    }

    @Nested
    class AuthorizationUrlTests {

        @Test
        void shouldBuildAuthorizationUrlWithValidJWT() throws Exception {
            when(configurationService.getAuthToAMCPublicEncryptionKey())
                    .thenReturn(constructTestPublicKey());
            Date expiryDate = new Date(NOW.getTime() + (5L * 1000));
            mockConfigurationService(expiryDate);
            mockAuthSessionItem();
            when(authSessionItem.getEmailAddress()).thenReturn(EMAIL);

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

            when(jwtService.signJWT(any(JWTClaimsSet.class), any(String.class)))
                    .thenThrow(
                            new JwtServiceException(
                                    "AWS SDK error when signing JWT",
                                    SdkException.builder().message("KMS Unreachable").build()));

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
            Date expiryDate = new Date(NOW.getTime() + (SESSION_EXPIRY * 1000));
            mockConfigurationService(expiryDate);
            mockAuthSessionItem();
            when(authSessionItem.getEmailAddress()).thenReturn(EMAIL);

            when(jwtService.signJWT(any(JWTClaimsSet.class), any(String.class)))
                    .thenThrow(
                            new JwtServiceException(
                                    "Failed to transcode signature", new JOSEException("Invalid")));

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

        @Test
        void shouldReturnEncryptionErrorWhenJoseExceptionOccursDuringEncryption() {
            when(configurationService.getAuthToAMCPublicEncryptionKey())
                    .thenReturn(constructTestPublicKey());
            Date expiryDate = new Date(NOW.getTime() + (SESSION_EXPIRY * 1000));
            mockConfigurationService(expiryDate);
            mockAuthSessionItem();
            when(authSessionItem.getEmailAddress()).thenReturn(EMAIL);
            when(jwtService.encryptJWT(any(), any()))
                    .thenThrow(
                            new JwtServiceException(
                                    "Encryption failed",
                                    new com.nimbusds.jose.JOSEException("Encryption error")));

            AMCService serviceWithMockJwt =
                    new AMCService(configurationService, nowClock, jwtService);

            Result<JwtFailureReason, String> result =
                    serviceWithMockJwt.buildAuthorizationUrl(
                            INTERNAL_PAIRWISE_ID,
                            new AMCScope[] {AMCScope.ACCOUNT_DELETE},
                            authSessionItem,
                            JOURNEY_ID,
                            PUBLIC_SUBJECT);

            assertTrue(result.isFailure());
            assertEquals(JwtFailureReason.ENCRYPTION_ERROR, result.getFailure());
        }

        @Test
        void shouldReturnUnknownEncryptionErrorForUnknownExceptionDuringEncryption() {
            when(configurationService.getAuthToAMCPublicEncryptionKey())
                    .thenReturn(constructTestPublicKey());
            Date expiryDate = new Date(NOW.getTime() + (SESSION_EXPIRY * 1000));
            mockConfigurationService(expiryDate);
            mockAuthSessionItem();
            when(authSessionItem.getEmailAddress()).thenReturn(EMAIL);
            when(jwtService.encryptJWT(any(), any()))
                    .thenThrow(new JwtServiceException("Unknown encryption error"));

            AMCService serviceWithMockJwt =
                    new AMCService(configurationService, nowClock, jwtService);

            Result<JwtFailureReason, String> result =
                    serviceWithMockJwt.buildAuthorizationUrl(
                            INTERNAL_PAIRWISE_ID,
                            new AMCScope[] {AMCScope.ACCOUNT_DELETE},
                            authSessionItem,
                            JOURNEY_ID,
                            PUBLIC_SUBJECT);

            assertTrue(result.isFailure());
            assertEquals(JwtFailureReason.UNKNOWN_JWT_ENCRYPTING_ERROR, result.getFailure());
        }

        @Test
        void shouldReturnJwtEncodingErrorWhenParseExceptionOccursDuringEncryption() {
            when(configurationService.getAuthToAMCPublicEncryptionKey())
                    .thenReturn(constructTestPublicKey());
            Date expiryDate = new Date(NOW.getTime() + (SESSION_EXPIRY * 1000));
            mockConfigurationService(expiryDate);
            mockAuthSessionItem();
            when(authSessionItem.getEmailAddress()).thenReturn(EMAIL);
            when(jwtService.encryptJWT(any(), any()))
                    .thenThrow(
                            new JwtServiceException(
                                    "Parse error", new java.text.ParseException("Invalid", 0)));

            AMCService serviceWithMockJwt =
                    new AMCService(configurationService, nowClock, jwtService);

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
        void shouldReturnJwtConstructionErrorForUnknownExceptionCause() {
            Date expiryDate = new Date(NOW.getTime() + (SESSION_EXPIRY * 1000));
            mockConfigurationService(expiryDate);
            mockAuthSessionItem();
            when(authSessionItem.getEmailAddress()).thenReturn(EMAIL);
            when(jwtService.signJWT(any(), any()))
                    .thenThrow(new JwtServiceException("Unknown error"));

            AMCService serviceWithMockJwt =
                    new AMCService(configurationService, nowClock, jwtService);

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
        void shouldHandleMultipleScopes() throws Exception {
            when(configurationService.getAuthToAMCPublicEncryptionKey())
                    .thenReturn(constructTestPublicKey());
            Date expiryDate = new Date(NOW.getTime() + (SESSION_EXPIRY * 1000));
            mockConfigurationService(expiryDate);
            mockAuthSessionItem();
            when(authSessionItem.getEmailAddress()).thenReturn(EMAIL);

            Result<JwtFailureReason, String> result =
                    amcService.buildAuthorizationUrl(
                            INTERNAL_PAIRWISE_ID,
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
            when(jwtService.signJWT(any(), any()))
                    .thenThrow(
                            new JwtServiceException(
                                    "Parse error", new java.text.ParseException("Invalid", 0)));

            AMCService serviceWithMockJwt =
                    new AMCService(configurationService, nowClock, jwtService);

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
        void shouldReturnJwtEncodingErrorWhenPublicKeyParsingFails() {
            when(configurationService.getAuthToAMCPublicEncryptionKey())
                    .thenReturn("invalid-pem-key");
            Date expiryDate = new Date(NOW.getTime() + (SESSION_EXPIRY * 1000));
            mockConfigurationService(expiryDate);
            mockAuthSessionItem();
            when(authSessionItem.getEmailAddress()).thenReturn(EMAIL);

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

        private void mockConfigurationService(Date expiryDate) {
            when(configurationService.getAuthIssuerClaim()).thenReturn(AUTH_ISSUER_CLAIM);
            when(configurationService.getAuthToAMAPIAudience()).thenReturn(AUTH_TO_AUTH_AUDIENCE);
            when(configurationService.getAuthToAMCAudience()).thenReturn(AUTH_TO_AMC_AUDIENCE);
            when(configurationService.getSessionExpiry()).thenReturn(SESSION_EXPIRY);
            when(configurationService.getAuthToAccountManagementPrivateSigningKeyAlias())
                    .thenReturn(ACCESS_TOKEN_KEY_ALIAS);
            when(configurationService.getAuthToAMCPrivateSigningKeyAlias())
                    .thenReturn(COMPOSITE_JWT_KEY_ALIAS);
            when(configurationService.getAMCRedirectURI()).thenReturn(REDIRECT_URI);
            when(configurationService.getAMCClientId()).thenReturn(AMC_CLIENT_ID);
            when(configurationService.getAMCAuthorizeURI())
                    .thenReturn(URI.create(AMC_AUTHORIZE_URI));
            when(nowClock.now()).thenReturn(NOW);
            when(nowClock.nowPlus(5L, ChronoUnit.MINUTES)).thenReturn(expiryDate);
        }

        private void mockAuthSessionItem() {
            when(authSessionItem.getClientId()).thenReturn(CLIENT_ID);
            when(authSessionItem.getSessionId()).thenReturn(SESSION_ID);
        }

        private void assertCompositeJWTClaims(JWTClaimsSet compositeClaims, Date expiryDate) {
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

    @Nested
    @DisplayName("Token Tests")
    class TokenTests {

        private ECKey signingKeyPair;

        @BeforeEach
        void setup() throws JOSEException {
            when(configurationService.getAMCClientId()).thenReturn(AMC_CLIENT_ID);
            when(configurationService.getAuthToAMCPrivateAudience())
                    .thenReturn(AUTH_TO_AMC_PRIVATE_AUDIENCE);
            when(configurationService.getSessionExpiry()).thenReturn(SESSION_EXPIRY);
            when(nowClock.now()).thenReturn(NOW);
            when(nowClock.nowPlus(SESSION_EXPIRY, ChronoUnit.SECONDS))
                    .thenReturn(Date.from(Instant.ofEpochSecond(NOW.getTime() + (3600 * 1000))));
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
            when(nowClock.now()).thenReturn(NOW);
            Date expiryDate = new Date(NOW.getTime() + (5L * 1000));
            when(nowClock.nowPlus(5L, ChronoUnit.MINUTES)).thenReturn(expiryDate);

            mockJwtSigning(Map.of(signingKeyPair.getKeyID(), signingKeyPair));

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
            assertEquals(NOW, claims.getIssueTime());
            assertEquals(NOW, claims.getNotBeforeTime());
            assertEquals(expiryDate, claims.getExpirationTime());
        }

        @Test
        void shouldReturnTokenRequestErrorWhenSigningFails() {
            var invalidKeyAlias = "invalid-key-alias";
            when(configurationService.getAuthToAMCPrivateSigningKeyAlias())
                    .thenReturn(invalidKeyAlias);
            when(nowClock.now()).thenReturn(NOW);
            Date expiryDate = new Date(NOW.getTime() + (5L * 1000));
            when(nowClock.nowPlus(5L, ChronoUnit.MINUTES)).thenReturn(expiryDate);

            when(jwtService.signJWT(any(JWTClaimsSet.class), eq(invalidKeyAlias)))
                    .thenThrow(
                            new JwtServiceException(
                                    "AWS SDK error when signing JWT",
                                    KmsException.create("Unable to sign", new RuntimeException())));

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

    private void mockJwtSigning(Map<String, ECKey> keysByAlias) {
        when(jwtService.signJWT(any(JWTClaimsSet.class), any(String.class)))
                .thenAnswer(
                        invocation -> {
                            JWTClaimsSet claims = invocation.getArgument(0);
                            String keyId = invocation.getArgument(1);

                            ECKey key = keysByAlias.get(keyId);
                            if (key == null) {
                                throw new IllegalArgumentException(
                                        "Unexpected key alias: " + keyId);
                            }

                            try {
                                SignedJWT signedJWT =
                                        new SignedJWT(
                                                new JWSHeader.Builder(JWSAlgorithm.ES256)
                                                        .type(com.nimbusds.jose.JOSEObjectType.JWT)
                                                        .keyID(key.getKeyID())
                                                        .build(),
                                                claims);
                                signedJWT.sign(new ECDSASigner(key));
                                return signedJWT;
                            } catch (JOSEException e) {
                                throw new RuntimeException(e);
                            }
                        });
    }

    private void mockJwtEncryption() {
        when(jwtService.encryptJWT(any(SignedJWT.class), any(RSAPublicKey.class)))
                .thenAnswer(
                        invocation -> {
                            SignedJWT signedJWT = invocation.getArgument(0);
                            RSAPublicKey publicKey = invocation.getArgument(1);
                            try {
                                JWEObject jweObject =
                                        new JWEObject(
                                                new JWEHeader.Builder(
                                                                JWEAlgorithm.RSA_OAEP_256,
                                                                EncryptionMethod.A256GCM)
                                                        .contentType("JWT")
                                                        .build(),
                                                new Payload(signedJWT));
                                jweObject.encrypt(new RSAEncrypter(publicKey));
                                return EncryptedJWT.parse(jweObject.serialize());
                            } catch (JOSEException | ParseException e) {
                                throw new RuntimeException(e);
                            }
                        });
    }
}
