package uk.gov.di.authentication.frontendapi.services;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.impl.ECDSA;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.core.exception.SdkException;
import software.amazon.awssdk.services.kms.model.SignRequest;
import software.amazon.awssdk.services.kms.model.SignResponse;
import uk.gov.di.authentication.frontendapi.entity.AMCAuthorizeFailureReason;
import uk.gov.di.authentication.frontendapi.entity.AMCScope;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.KmsConnectionService;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
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
    private static final String EMAIL = "test@example.com";
    private static final String JOURNEY_ID = "test-journey-id";
    private static final String PUBLIC_SUBJECT = "test-public-subject";
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
        amcAuthorizationService =
                new AMCAuthorizationService(configurationService, nowClock, kmsConnectionService);
    }

    @Test
    void shouldCreateCompositeJWTClaimsWithValidAccessToken() throws Exception {
        ECKey ecSigningKey =
                new ECKeyGenerator(Curve.P_256).algorithm(JWSAlgorithm.ES256).generate();
        Date expiryDate = new Date(NOW.getTime() + (SESSION_EXPIRY * 1000));
        mockConfigurationService(expiryDate);
        mockAuthSessionItem();
        mockKmsSigningToUseKey(ecSigningKey);
        when(authSessionItem.getEmailAddress()).thenReturn(EMAIL);

        Result<AMCAuthorizeFailureReason, JWTClaimsSet> result =
                amcAuthorizationService.createCompositeJWT(
                        new Subject(INTERNAL_PAIRWISE_ID),
                        new AMCScope[] {AMCScope.ACCOUNT_DELETE},
                        authSessionItem,
                        JOURNEY_ID,
                        PUBLIC_SUBJECT);

        assertTrue(result.isSuccess());
        JWTClaimsSet compositeClaims = result.getSuccess();

        assertCompositeJWTClaims(compositeClaims, expiryDate);

        @SuppressWarnings("unchecked")
        Result<AMCAuthorizeFailureReason, BearerAccessToken> accessTokenResult =
                (Result<AMCAuthorizeFailureReason, BearerAccessToken>)
                        compositeClaims.getClaim("access_token");

        BearerAccessToken bearerToken = accessTokenResult.getSuccess();

        assertEquals(SESSION_EXPIRY, bearerToken.getLifetime());
        assertTrue(bearerToken.getScope().contains(AMCScope.ACCOUNT_DELETE.getValue()));

        SignedJWT signedJWT = SignedJWT.parse(bearerToken.getValue());
        assertTrue(signedJWT.verify(new ECDSAVerifier(ecSigningKey.toECPublicKey())));

        JWTClaimsSet accessTokenClaims = signedJWT.getJWTClaimsSet();
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

        Result<AMCAuthorizeFailureReason, JWTClaimsSet> result =
                amcAuthorizationService.createCompositeJWT(
                        new Subject(INTERNAL_PAIRWISE_ID),
                        new AMCScope[] {AMCScope.ACCOUNT_DELETE},
                        authSessionItem,
                        JOURNEY_ID,
                        PUBLIC_SUBJECT);

        assertTrue(result.isFailure());
        assertEquals(AMCAuthorizeFailureReason.KMS_ERROR, result.getFailure());
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
                                .signature(
                                        SdkBytes.fromByteArray(
                                                new byte[] {0x00, 0x01})) // Invalid bytes
                                .build());

        Result<AMCAuthorizeFailureReason, JWTClaimsSet> result =
                amcAuthorizationService.createCompositeJWT(
                        new Subject(INTERNAL_PAIRWISE_ID),
                        new AMCScope[] {AMCScope.ACCOUNT_DELETE},
                        authSessionItem,
                        JOURNEY_ID,
                        PUBLIC_SUBJECT);

        assertTrue(result.isFailure());
        assertEquals(AMCAuthorizeFailureReason.TRANSCODING_ERROR, result.getFailure());
    }

    private void mockKmsSigningToUseKey(ECKey ecKey) {
        when(kmsConnectionService.sign(any(SignRequest.class)))
                .thenAnswer(
                        invocation -> {
                            String input =
                                    ((SignRequest) invocation.getArgument(0))
                                            .message()
                                            .asUtf8String();

                            byte[] signature =
                                    new ECDSASigner(ecKey)
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
                .thenReturn("test-key-alias");
        when(configurationService.getAMCRedirectURI()).thenReturn(REDIRECT_URI);
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
}
