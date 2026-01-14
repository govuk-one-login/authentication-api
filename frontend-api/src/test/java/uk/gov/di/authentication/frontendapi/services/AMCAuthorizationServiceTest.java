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
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AMCAuthorizationServiceTest {
    private AMCAuthorizationService amcAuthorizationService;
    private static final String INTERNAL_PAIRWISE_ID =
            "urn:fdc:gov.uk:2022:xH7hrtJCgdi2NEF7TXcOC6SMz8DohdoLo9hWqQMWPRk";
    private static final String AUTH_ISSUER_CLAIM = "https://signin.account.gov.uk/";
    private static final String AUTH_TO_AUTH_AUDIENCE = "https://api.manage.account.gov.uk";
    private static final String CLIENT_ID = "test-client-id";
    private static final String SESSION_ID = "test-session-id";
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
    void shouldCreateAccessTokenWithValidJWTClaims() throws Exception {
        ECKey ecSigningKey =
                new ECKeyGenerator(Curve.P_256).algorithm(JWSAlgorithm.ES256).generate();
        Date expiryDate = new Date(NOW.getTime() + (SESSION_EXPIRY * 1000));
        mockConfigurationService(expiryDate);
        mockAuthSessionItem();
        mockKmsSigningToUseKey(ecSigningKey);

        Result<AMCAuthorizeFailureReason, BearerAccessToken> result =
                amcAuthorizationService.createAccessToken(
                        new Subject(INTERNAL_PAIRWISE_ID),
                        new AMCScope[] {AMCScope.ACCOUNT_DELETE},
                        authSessionItem);

        assertTrue(result.isSuccess());
        BearerAccessToken bearerToken = result.getSuccess();

        assertEquals(SESSION_EXPIRY, bearerToken.getLifetime());
        assertTrue(bearerToken.getScope().contains(AMCScope.ACCOUNT_DELETE.getValue()));

        SignedJWT signedJWT = SignedJWT.parse(bearerToken.getValue());
        assertTrue(signedJWT.verify(new ECDSAVerifier(ecSigningKey.toECPublicKey())));

        JWTClaimsSet claims = signedJWT.getJWTClaimsSet();
        assertAll(
                "JWT Claims",
                () -> assertEquals(AUTH_ISSUER_CLAIM, claims.getIssuer()),
                () -> assertEquals(INTERNAL_PAIRWISE_ID, claims.getSubject()),
                () -> assertEquals(List.of(AUTH_TO_AUTH_AUDIENCE), claims.getAudience()),
                () ->
                        assertEquals(
                                List.of(AMCScope.ACCOUNT_DELETE.getValue()),
                                claims.getClaim("scope")),
                () -> assertEquals(CLIENT_ID, claims.getClaim("client_id")),
                () -> assertEquals(SESSION_ID, claims.getClaim("sid")),
                () -> assertEquals(NOW, claims.getIssueTime()),
                () -> assertEquals(NOW, claims.getNotBeforeTime()),
                () -> assertEquals(expiryDate, claims.getExpirationTime()),
                () -> assertDoesNotThrow(() -> UUID.fromString(claims.getJWTID())));
    }

    @Test
    void shouldReturnFailureWhenKmsSigningFails() {
        when(configurationService.getSessionExpiry()).thenReturn(SESSION_EXPIRY);
        when(nowClock.now()).thenReturn(NOW);
        when(nowClock.nowPlus(anyLong(), any())).thenReturn(new Date());
        when(configurationService.getAuthToAccountManagementPrivateSigningKeyAlias())
                .thenReturn("key-alias");

        when(kmsConnectionService.sign(any(SignRequest.class)))
                .thenThrow(SdkException.builder().message("KMS Unreachable").build());

        Result<AMCAuthorizeFailureReason, BearerAccessToken> result =
                amcAuthorizationService.createAccessToken(
                        new Subject(INTERNAL_PAIRWISE_ID),
                        new AMCScope[] {AMCScope.ACCOUNT_DELETE},
                        authSessionItem);

        assertTrue(result.isFailure());
        assertEquals(AMCAuthorizeFailureReason.KMS_ERROR, result.getFailure());
    }

    @Test
    void shouldReturnFailureWhenSignatureTranscodingFails() {
        when(configurationService.getSessionExpiry()).thenReturn(SESSION_EXPIRY);
        when(nowClock.now()).thenReturn(NOW);
        when(nowClock.nowPlus(anyLong(), any())).thenReturn(new Date());
        when(configurationService.getAuthToAccountManagementPrivateSigningKeyAlias())
                .thenReturn("key-alias");

        when(kmsConnectionService.sign(any(SignRequest.class)))
                .thenReturn(
                        SignResponse.builder()
                                .signature(
                                        SdkBytes.fromByteArray(
                                                new byte[] {0x00, 0x01})) // Invalid bytes
                                .build());

        Result<AMCAuthorizeFailureReason, BearerAccessToken> result =
                amcAuthorizationService.createAccessToken(
                        new Subject(INTERNAL_PAIRWISE_ID),
                        new AMCScope[] {AMCScope.ACCOUNT_DELETE},
                        authSessionItem);

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
        when(configurationService.getSessionExpiry()).thenReturn(SESSION_EXPIRY);
        when(configurationService.getAuthToAccountManagementPrivateSigningKeyAlias())
                .thenReturn("test-key-alias");
        when(nowClock.now()).thenReturn(NOW);
        when(nowClock.nowPlus(SESSION_EXPIRY, ChronoUnit.SECONDS)).thenReturn(expiryDate);
    }

    private void mockAuthSessionItem() {
        when(authSessionItem.getClientId()).thenReturn(CLIENT_ID);
        when(authSessionItem.getSessionId()).thenReturn(SESSION_ID);
    }
}
