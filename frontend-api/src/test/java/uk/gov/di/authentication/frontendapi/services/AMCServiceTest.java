package uk.gov.di.authentication.frontendapi.services;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.PrivateKeyJWT;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.authentication.frontendapi.entity.JwtFailureReason;
import uk.gov.di.authentication.frontendapi.entity.amc.AMCFailureReason;
import uk.gov.di.authentication.frontendapi.entity.amc.AMCScope;
import uk.gov.di.authentication.frontendapi.entity.amc.AccessTokenConfig;
import uk.gov.di.authentication.frontendapi.entity.amc.AccessTokenScope;
import uk.gov.di.authentication.frontendapi.entity.amc.AccountDataScope;
import uk.gov.di.authentication.frontendapi.entity.amc.AccountManagementScope;
import uk.gov.di.authentication.frontendapi.entity.amc.JourneyOutcomeError;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.helpers.HashHelper;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
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
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.CLIENT_ID;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.EMAIL;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.SESSION_ID;
import static uk.gov.di.authentication.sharedtest.helper.KeyPairHelper.GENERATE_RSA_KEY_PAIR;

class AMCServiceTest {
    private AMCService amcService;
    private static final String INTERNAL_PAIRWISE_ID =
            "urn:fdc:gov.uk:2022:xH7hrtJCgdi2NEF7TXcOC6SMz8DohdoLo9hWqQMWPRk";
    private static final String AUTH_ISSUER_CLAIM = "https://signin.account.gov.uk/";
    private static final String AUTH_TO_AUTH_AUDIENCE = "https://api.manage.account.gov.uk";
    private static final String AUTH_TO_AMC_PUBLIC_AUDIENCE =
            "https://manage.account.gov.uk/authorize";
    private static final String AUTH_TO_AMC_PRIVATE_AUDIENCE = "https://amc.account.gov.uk";
    private static final String RESPONSE_TYPE = "code";
    private static final String REDIRECT_URI = "https://example.com/callback";
    private static final String ACCESS_TOKEN_AUDIENCE = "access-token-audience";
    private static final String SECOND_ACCESS_TOKEN_AUDIENCE = "second-access-token-audience";
    private static final String AMC_CLIENT_ID = "amc-client-id";
    private static final String AMC_AUTHORIZE_URI = "https://amc.account.gov.uk/authorize";
    private static final String AMC_JWKS_URL = "https://amc.account.gov.uk/.well-known/jwks.json";
    private static final URI TOKEN_ENDPOINT_URI = URI.create("https://amc.account.gov.uk/token");
    private static final String PUBLIC_SUBJECT = "test-public-subject";
    private static final String ACCESS_TOKEN_KEY_ALIAS = "test-key-alias";
    private static final String OTHER_ACCESS_TOKEN_KEY_ALIAS = "other-test-key-alias";
    private static final String COMPOSITE_JWT_KEY_ALIAS = "auth-to-amc-test-key-alias";
    private static final KeyPair TEST_ENCRYPTION_KEY_PAIR = GENERATE_RSA_KEY_PAIR();
    private static final RSAPublicKey TEST_PUBLIC_ENCRYPTION_KEY =
            (RSAPublicKey) TEST_ENCRYPTION_KEY_PAIR.getPublic();
    private static final RSAPrivateKey TEST_PRIVATE_ENCRYPTION_KEY =
            (RSAPrivateKey) TEST_ENCRYPTION_KEY_PAIR.getPrivate();
    private AuthSessionItem authSessionItem;
    private static final String AUTH_CODE = "1234";
    private static final String USED_REDIRECT_URL = "https://signin.account.gov.uk/amc-callback";
    private static final List<AccessTokenConfig> ACCESS_TOKEN_CONFIG =
            List.of(
                    new AccessTokenConfig(
                            "account_management_api_access_token",
                            AccountManagementScope.ACCOUNT_DELETE,
                            ACCESS_TOKEN_AUDIENCE,
                            ACCESS_TOKEN_KEY_ALIAS));
    private final JWKSource<SecurityContext> jwkSource = mock(JWKSource.class);

    // Ensure 0 milliseconds for JWT compatibility
    private static final Instant NOW_INSTANT = Instant.now().truncatedTo(ChronoUnit.SECONDS);
    private static final Date NOW = Date.from(NOW_INSTANT);
    private static final Long CLIENT_ASSERTION_LIFETIME = 5L;
    private static final Date JWT_EXPIRY =
            Date.from(NOW_INSTANT.plus(CLIENT_ASSERTION_LIFETIME, ChronoUnit.MINUTES));
    private static final NowHelper.NowClock NOW_CLOCK =
            new NowHelper.NowClock(Clock.fixed(NOW_INSTANT, ZoneOffset.UTC));
    private static final State STATE = new State();

    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final JwtService jwtService = mock(JwtService.class);
    private final AccessTokenConstructorService accessTokenConstructorService =
            mock(AccessTokenConstructorService.class);
    private ECKey accessTokenKey;
    private ECKey otherAccessTokenKey;
    private ECKey compositeJWTKey;

    @BeforeEach
    void setup() throws Exception {
        amcService =
                new AMCService(
                        configurationService, NOW_CLOCK, jwtService, accessTokenConstructorService);
        accessTokenKey = new ECKeyGenerator(Curve.P_256).algorithm(JWSAlgorithm.ES256).generate();
        compositeJWTKey = new ECKeyGenerator(Curve.P_256).algorithm(JWSAlgorithm.ES256).generate();
        otherAccessTokenKey =
                new ECKeyGenerator(Curve.P_256).algorithm(JWSAlgorithm.ES256).generate();
        mockJwtSigning(Map.of(COMPOSITE_JWT_KEY_ALIAS, compositeJWTKey));
        mockAccessTokenCreation();
        mockJwtEncryption();
        authSessionItem =
                new AuthSessionItem()
                        .withClientId(CLIENT_ID)
                        .withSessionId(SESSION_ID)
                        .withEmailAddress(EMAIL);
        mockConfigurationService();
    }

    private void mockConfigurationService() throws MalformedURLException {
        when(configurationService.getAuthIssuerClaim()).thenReturn(AUTH_ISSUER_CLAIM);
        when(configurationService.getAuthToAMApiAudience()).thenReturn(AUTH_TO_AUTH_AUDIENCE);
        when(configurationService.getAuthToAMCPublicAudience())
                .thenReturn(AUTH_TO_AMC_PUBLIC_AUDIENCE);
        when(configurationService.getAuthToAccountManagementSigningKey())
                .thenReturn(ACCESS_TOKEN_KEY_ALIAS);
        when(configurationService.getAuthToAMCTransportJWTSigningKey())
                .thenReturn(COMPOSITE_JWT_KEY_ALIAS);
        when(configurationService.getAMCSfadRedirectURI()).thenReturn(REDIRECT_URI);
        when(configurationService.getAMCClientId()).thenReturn(AMC_CLIENT_ID);
        when(configurationService.getAMCAuthorizeURI()).thenReturn(URI.create(AMC_AUTHORIZE_URI));
        when(configurationService.getAmcJwksUrl()).thenReturn(URI.create(AMC_JWKS_URL).toURL());
    }

    @Nested
    class AuthorizationUrlTests {

        private static Stream<Arguments> accessTokenConfigs() {
            return Stream.of(
                    Arguments.of(
                            List.of(
                                    new AccessTokenConfig(
                                            "account_management_api_access_token",
                                            AccountManagementScope.ACCOUNT_DELETE,
                                            ACCESS_TOKEN_AUDIENCE,
                                            ACCESS_TOKEN_KEY_ALIAS))),
                    Arguments.of(
                            List.of(
                                    new AccessTokenConfig(
                                            "account_management_api_access_token",
                                            AccountManagementScope.ACCOUNT_DELETE,
                                            ACCESS_TOKEN_AUDIENCE,
                                            OTHER_ACCESS_TOKEN_KEY_ALIAS),
                                    new AccessTokenConfig(
                                            "account_data_api_access_token",
                                            AccountDataScope.PASSKEY_CREATE,
                                            SECOND_ACCESS_TOKEN_AUDIENCE,
                                            ACCESS_TOKEN_KEY_ALIAS))));
        }

        @ParameterizedTest
        @MethodSource("accessTokenConfigs")
        void shouldBuildAuthorizationUrlWithValidJWT(List<AccessTokenConfig> accessTokenConfigs)
                throws Exception {

            var result =
                    amcService.buildAuthorizationResult(
                            INTERNAL_PAIRWISE_ID,
                            AMCScope.ACCOUNT_DELETE,
                            authSessionItem,
                            PUBLIC_SUBJECT,
                            REDIRECT_URI,
                            accessTokenConfigs,
                            TEST_PUBLIC_ENCRYPTION_KEY,
                            STATE);

            assertTrue(result.isSuccess());
            String authorizationUrl = result.getSuccess().url();
            assertTrue(authorizationUrl.startsWith(AMC_AUTHORIZE_URI));

            SignedJWT compositeJWT = extractSignedJwtFromAuthUrl(authorizationUrl);

            String amcCookie = result.getSuccess().amcCookie();
            assertEquals(HashHelper.hashSha256String(compositeJWT.serialize()), amcCookie);

            assertTrue(compositeJWT.verify(new ECDSAVerifier(compositeJWTKey.toECPublicKey())));

            JWTClaimsSet compositeClaims = compositeJWT.getJWTClaimsSet();
            assertCompositeJWTClaims(compositeClaims);

            for (AccessTokenConfig accessTokenConfig : accessTokenConfigs) {
                var accessTokenName = accessTokenConfig.accessTokenName();
                var accessTokenValue = compositeClaims.getClaim(accessTokenName).toString();

                SignedJWT accessTokenJWT = SignedJWT.parse(accessTokenValue);
                if (accessTokenConfig.signingKey().equals(ACCESS_TOKEN_KEY_ALIAS)) {
                    assertTrue(
                            accessTokenJWT.verify(
                                    new ECDSAVerifier(accessTokenKey.toECPublicKey())));
                } else {
                    assertTrue(
                            accessTokenJWT.verify(
                                    new ECDSAVerifier(otherAccessTokenKey.toECPublicKey())));
                }

                JWTClaimsSet accessTokenClaims = accessTokenJWT.getJWTClaimsSet();
                assertAccessTokenClaims(
                        accessTokenConfig.scope(), accessTokenConfig.audience(), accessTokenClaims);
            }
        }

        @Test
        void shouldReturnFailureWhenKmsSigningFails() {
            when(jwtService.signJWT(any(JWTClaimsSet.class), any(String.class)))
                    .thenReturn(Result.failure(JwtFailureReason.SIGNING_ERROR));

            var result =
                    amcService.buildAuthorizationResult(
                            INTERNAL_PAIRWISE_ID,
                            AMCScope.ACCOUNT_DELETE,
                            authSessionItem,
                            PUBLIC_SUBJECT,
                            REDIRECT_URI,
                            ACCESS_TOKEN_CONFIG,
                            TEST_PUBLIC_ENCRYPTION_KEY,
                            STATE);

            assertTrue(result.isFailure());
            assertEquals(AMCFailureReason.SIGNING_ERROR, result.getFailure());
        }

        @Test
        void shouldReturnFailureWhenSignatureTranscodingFails() {
            when(jwtService.signJWT(any(JWTClaimsSet.class), any(String.class)))
                    .thenReturn(Result.failure(JwtFailureReason.TRANSCODING_ERROR));

            var result =
                    amcService.buildAuthorizationResult(
                            INTERNAL_PAIRWISE_ID,
                            AMCScope.ACCOUNT_DELETE,
                            authSessionItem,
                            PUBLIC_SUBJECT,
                            REDIRECT_URI,
                            ACCESS_TOKEN_CONFIG,
                            TEST_PUBLIC_ENCRYPTION_KEY,
                            STATE);

            assertTrue(result.isFailure());
            assertEquals(AMCFailureReason.TRANSCODING_ERROR, result.getFailure());
        }

        private static Stream<Arguments> jwtFailureReasonsToAMCFailureReasons() {
            return Stream.of(
                    Arguments.of(
                            JwtFailureReason.UNKNOWN_JWT_SIGNING_ERROR,
                            AMCFailureReason.UNKNOWN_JWT_SIGNING_ERROR),
                    Arguments.of(
                            JwtFailureReason.JWT_ENCODING_ERROR,
                            AMCFailureReason.JWT_ENCODING_ERROR),
                    Arguments.of(
                            JwtFailureReason.ENCRYPTION_ERROR, AMCFailureReason.ENCRYPTION_ERROR),
                    Arguments.of(
                            JwtFailureReason.UNKNOWN_JWT_ENCRYPTING_ERROR,
                            AMCFailureReason.UNKNOWN_JWT_ENCRYPTING_ERROR),
                    Arguments.of(
                            JwtFailureReason.JWT_ENCODING_ERROR,
                            AMCFailureReason.JWT_ENCODING_ERROR));
        }

        @ParameterizedTest
        @MethodSource("jwtFailureReasonsToAMCFailureReasons")
        void shouldMapJwtFailureReasonsToAMCFailureReason(
                JwtFailureReason signingFailureReason, AMCFailureReason expectedFailureReason) {
            when(jwtService.signJWT(any(), any())).thenReturn(Result.failure(signingFailureReason));

            AMCService serviceWithMockJwt =
                    new AMCService(
                            configurationService,
                            NOW_CLOCK,
                            jwtService,
                            accessTokenConstructorService);

            var result =
                    serviceWithMockJwt.buildAuthorizationResult(
                            INTERNAL_PAIRWISE_ID,
                            AMCScope.ACCOUNT_DELETE,
                            authSessionItem,
                            PUBLIC_SUBJECT,
                            REDIRECT_URI,
                            ACCESS_TOKEN_CONFIG,
                            TEST_PUBLIC_ENCRYPTION_KEY,
                            STATE);

            assertTrue(result.isFailure());
            assertEquals(expectedFailureReason, result.getFailure());
        }

        @ParameterizedTest
        @MethodSource("jwtFailureReasonsToAMCFailureReasons")
        void shouldMapJwtFailureReasonsFromCreateSignedAccessTokenToAMCFailureReason(
                JwtFailureReason jwtFailureReason, AMCFailureReason expectedFailureReason) {
            var externalApiAccessTokenService = mock(AccessTokenConstructorService.class);
            when(externalApiAccessTokenService.createSignedAccessToken(
                            any(), any(), any(), any(), any(), any(), any(), any(), any()))
                    .thenReturn(Result.failure(jwtFailureReason));

            AMCService serviceWithMockJwt =
                    new AMCService(
                            configurationService,
                            NOW_CLOCK,
                            jwtService,
                            externalApiAccessTokenService);

            var result =
                    serviceWithMockJwt.buildAuthorizationResult(
                            INTERNAL_PAIRWISE_ID,
                            AMCScope.ACCOUNT_DELETE,
                            authSessionItem,
                            PUBLIC_SUBJECT,
                            REDIRECT_URI,
                            ACCESS_TOKEN_CONFIG,
                            TEST_PUBLIC_ENCRYPTION_KEY,
                            STATE);

            assertTrue(result.isFailure());
            assertEquals(expectedFailureReason, result.getFailure());
        }

        private void assertCompositeJWTClaims(JWTClaimsSet compositeClaims) {
            assertAll(
                    "Composite JWT Claims",
                    () -> assertEquals(AUTH_ISSUER_CLAIM, compositeClaims.getIssuer()),
                    () ->
                            assertEquals(
                                    List.of(AUTH_TO_AMC_PUBLIC_AUDIENCE),
                                    compositeClaims.getAudience()),
                    () -> assertEquals(AMC_CLIENT_ID, compositeClaims.getClaim("client_id")),
                    () -> assertEquals(RESPONSE_TYPE, compositeClaims.getClaim("response_type")),
                    () -> assertEquals(REDIRECT_URI, compositeClaims.getClaim("redirect_uri")),
                    () ->
                            assertEquals(
                                    AMCScope.ACCOUNT_DELETE.getValue(),
                                    compositeClaims.getClaim("scope")),
                    () -> assertEquals(STATE.getValue(), compositeClaims.getClaim("state")),
                    () -> assertEquals(INTERNAL_PAIRWISE_ID, compositeClaims.getSubject()),
                    () -> assertEquals(EMAIL, compositeClaims.getClaim("email")),
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

        private void assertAccessTokenClaims(
                AccessTokenScope expectedScope,
                String expectedAudience,
                JWTClaimsSet accessTokenClaims) {
            assertAll(
                    "Access Token Claims",
                    () -> assertEquals(AUTH_ISSUER_CLAIM, accessTokenClaims.getIssuer()),
                    () -> assertEquals(PUBLIC_SUBJECT, accessTokenClaims.getSubject()),
                    () -> assertEquals(List.of(expectedAudience), accessTokenClaims.getAudience()),
                    () ->
                            assertEquals(
                                    expectedScope.getValue(), accessTokenClaims.getClaim("scope")),
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

        private SignedJWT extractSignedJwtFromAuthUrl(String authorizationUrl) throws Exception {
            AuthorizationRequest authRequest = AuthorizationRequest.parse(authorizationUrl);
            EncryptedJWT encryptedJWT = (EncryptedJWT) authRequest.getRequestObject();
            encryptedJWT.decrypt(new RSADecrypter(TEST_PRIVATE_ENCRYPTION_KEY));
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
            when(configurationService.getAMCTokenEndpointURI()).thenReturn(TOKEN_ENDPOINT_URI);
            signingKeyPair =
                    new ECKeyGenerator(Curve.P_256)
                            .algorithm(JWSAlgorithm.ES256)
                            .keyIDFromThumbprint(true)
                            .generate();
        }

        @Test
        void shouldBuildTokenRequest() throws ParseException, JOSEException {
            when(configurationService.getAuthToAMCTransportJWTSigningKey())
                    .thenReturn(signingKeyPair.getKeyID());

            mockJwtSigning(Map.of(signingKeyPair.getKeyID(), signingKeyPair));

            var result = amcService.buildTokenRequest(AUTH_CODE, USED_REDIRECT_URL).getSuccess();

            var authGrant = (AuthorizationCodeGrant) result.getAuthorizationGrant();
            assertEquals(AUTH_CODE, authGrant.getAuthorizationCode().toString());
            assertEquals(URI.create(USED_REDIRECT_URL), authGrant.getRedirectionURI());

            assertEquals(TOKEN_ENDPOINT_URI, result.getEndpointURI());

            ClientAuthentication clientAuth = result.getClientAuthentication();
            PrivateKeyJWT privateKeyJWT = (PrivateKeyJWT) clientAuth;
            SignedJWT signedJWT = privateKeyJWT.getClientAssertion();

            assertTrue(signedJWT.verify(new ECDSAVerifier(signingKeyPair.toECPublicKey())));

            JWTClaimsSet claims = signedJWT.getJWTClaimsSet();

            assertEquals(AMC_CLIENT_ID, claims.getIssuer());
            assertEquals(AMC_CLIENT_ID, claims.getSubject());
            assertEquals(List.of(AUTH_TO_AMC_PRIVATE_AUDIENCE), claims.getAudience());
            assertInstanceOf(String.class, claims.getJWTID());
            assertEquals(NOW.toInstant(), claims.getIssueTime().toInstant());
            assertEquals(NOW.toInstant(), claims.getNotBeforeTime().toInstant());
            assertEquals(JWT_EXPIRY.toInstant(), claims.getExpirationTime().toInstant());
        }

        @Test
        void shouldReturnTokenRequestErrorWhenSigningFails() {
            var invalidKeyAlias = "invalid-key-alias";
            when(configurationService.getAuthToAMCTransportJWTSigningKey())
                    .thenReturn(invalidKeyAlias);

            when(jwtService.signJWT(any(JWTClaimsSet.class), eq(invalidKeyAlias)))
                    .thenReturn(Result.failure(JwtFailureReason.SIGNING_ERROR));

            Result<AMCFailureReason, TokenRequest> result =
                    amcService.buildTokenRequest(AUTH_CODE, USED_REDIRECT_URL);

            assertTrue(result.isFailure());
            assertEquals(AMCFailureReason.SIGNING_ERROR, result.getFailure());
        }
    }

    @Nested
    @DisplayName("Journey Outcome Tests")
    class JourneyOutcomeTests {
        private UserInfoRequest userInfoRequest;
        private HTTPRequest httpRequestFromUserInfoRequest;

        @BeforeEach
        void setup() {
            userInfoRequest = mock(UserInfoRequest.class);
            httpRequestFromUserInfoRequest = mock(HTTPRequest.class);
            when(userInfoRequest.toHTTPRequest()).thenReturn(httpRequestFromUserInfoRequest);
        }

        @Test
        void shouldSendAJourneyOutcomeRequest() throws IOException {
            var response = new HTTPResponse(200);
            when(httpRequestFromUserInfoRequest.send()).thenReturn(response);

            var result = amcService.requestJourneyOutcome(userInfoRequest, Map.of());

            assertEquals(Result.success(response), result);
        }

        @Test
        void shouldReturnAnErrorForAnUnsuccessfulRequest() throws IOException {
            var response = new HTTPResponse(400);
            when(httpRequestFromUserInfoRequest.send()).thenReturn(response);

            var result = amcService.requestJourneyOutcome(userInfoRequest, Map.of());

            assertEquals(
                    Result.failure(JourneyOutcomeError.ERROR_RESPONSE_FROM_JOURNEY_OUTCOME),
                    result);
        }

        @Test
        void shouldReturnAnErrorForAnIOException() throws IOException {
            when(httpRequestFromUserInfoRequest.send()).thenThrow(new IOException("Uh oh"));

            var result = amcService.requestJourneyOutcome(userInfoRequest, Map.of());

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
                                return Result.success(signedJWT);
                            } catch (JOSEException e) {
                                throw new RuntimeException(e);
                            }
                        });
    }

    private void mockJwtEncryption() throws KeySourceException {
        when(jwkSource.get(any(JWKSelector.class), isNull()))
                .thenReturn(List.of(new RSAKey.Builder(TEST_PUBLIC_ENCRYPTION_KEY).build()));
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
                                return Result.success(EncryptedJWT.parse(jweObject.serialize()));
                            } catch (JOSEException | ParseException e) {
                                throw new RuntimeException(e);
                            }
                        });
    }

    private void mockAccessTokenCreation() {
        when(accessTokenConstructorService.createSignedAccessToken(
                        any(), any(), any(), any(), any(), any(), any(), any(), any()))
                .thenAnswer(
                        invocation -> {
                            String publicSubjectId = invocation.getArgument(0);
                            AccessTokenScope scope = invocation.getArgument(1);
                            String sessionId = invocation.getArgument(2);
                            Date issueTime = invocation.getArgument(3);
                            Date expiryDate = invocation.getArgument(4);
                            String audience = invocation.getArgument(5);
                            String issuer = invocation.getArgument(6);
                            String clientId = invocation.getArgument(7);
                            String signingKeyAlias = invocation.getArgument(8);

                            ECKey key =
                                    Map.of(
                                                    ACCESS_TOKEN_KEY_ALIAS, accessTokenKey,
                                                    OTHER_ACCESS_TOKEN_KEY_ALIAS,
                                                            otherAccessTokenKey)
                                            .get(signingKeyAlias);

                            var claims =
                                    new JWTClaimsSet.Builder()
                                            .claim("scope", scope.getValue())
                                            .issuer(issuer)
                                            .audience(audience)
                                            .expirationTime(expiryDate)
                                            .issueTime(issueTime)
                                            .notBeforeTime(issueTime)
                                            .subject(publicSubjectId)
                                            .claim("client_id", clientId)
                                            .claim("sid", sessionId)
                                            .jwtID(UUID.randomUUID().toString())
                                            .build();

                            SignedJWT signedJWT =
                                    new SignedJWT(
                                            new JWSHeader.Builder(JWSAlgorithm.ES256)
                                                    .type(com.nimbusds.jose.JOSEObjectType.JWT)
                                                    .keyID(key.getKeyID())
                                                    .build(),
                                            claims);
                            signedJWT.sign(new ECDSASigner(key));

                            return Result.success(
                                    new BearerAccessToken(
                                            signedJWT.serialize(),
                                            3600L,
                                            new Scope(scope.getValue())));
                        });
    }
}
