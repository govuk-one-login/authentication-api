package uk.gov.di.orchestration.shared.services;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import uk.gov.di.orchestration.shared.helpers.NowHelper;
import uk.gov.di.orchestration.sharedtest.helper.TokenGeneratorHelper;

import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

// QualityGateUnitTest
class TokenValidationServiceTest {

    private final JwksService jwksService = mock(JwksService.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final TokenValidationService tokenValidationService =
            new TokenValidationService(jwksService, configurationService);
    private static final Subject SUBJECT = new Subject("some-subject");
    private static final List<String> SCOPES = List.of("openid", "email", "phone");
    private static final List<String> REFRESH_SCOPES = List.of("openid", "email", "offline_access");
    private static final String CLIENT_ID = "client-id";
    private static final String BASE_URL = "https://example.com";
    private static final String KEY_ID = "14342354354353";
    private static final String NEW_V2_KEY_ID = "14342334554354";
    private static final String OLD_STORED_KEY_ID = "14442634554354";
    private static final String FAILED_KEY_ID = "14342354354355";
    private ECKey ecJWK;
    private JWSSigner newV2Signer;
    private ECKey newV2ECJWK;

    @BeforeEach
    void setUp() throws JOSEException {
        ecJWK = generateECKeyPair();
        when(jwksService.getPublicTokenJwkWithOpaqueId()).thenReturn(ecJWK.toPublicJWK());

        newV2ECJWK = generateCustomECKeyPair(NEW_V2_KEY_ID);
        newV2Signer = new ECDSASigner(newV2ECJWK);
        when(jwksService.getNextPublicTokenJwkWithOpaqueIdV2()).thenReturn(newV2ECJWK);
    }

    // QualityGateRegressionTest
    @Test
    void shouldSuccessfullyValidateIDToken() {
        Date expiryDate = NowHelper.nowPlus(2, ChronoUnit.MINUTES);
        SignedJWT signedIdToken = createSignedIdTokenWithV2Key(expiryDate);
        assertTrue(tokenValidationService.isTokenSignatureValid(signedIdToken.serialize()));
    }

    // QualityGateRegressionTest
    @Test
    void shouldNotFailSignatureValidationIfIdTokenHasExpired() {
        Date expiryDate = NowHelper.nowMinus(2, ChronoUnit.MINUTES);
        SignedJWT signedIdToken = createSignedIdTokenWithV2Key(expiryDate);
        assertTrue(tokenValidationService.isTokenSignatureValid(signedIdToken.serialize()));
    }

    // QualityGateRegressionTest
    @Test
    void shouldSuccessfullyValidateNewECKeyV2AccessToken() {
        SignedJWT signedAccessToken = createSignedAccessTokenWithV2Signer();
        assertTrue(
                tokenValidationService.isTokenSignatureValid(
                        new BearerAccessToken(signedAccessToken.serialize()).getValue()));
    }

    // QualityGateRegressionTest
    @Test
    void shouldFailToValidateECKeyAccessTokenIfKeyIdInvalid() throws JOSEException {
        var failedECKey = generateCustomECKeyPair(FAILED_KEY_ID);
        var ecSigner = new ECDSASigner(failedECKey);

        SignedJWT signedAccessToken = createCustomSignedAccessToken(ecSigner, FAILED_KEY_ID);
        assertFalse(
                tokenValidationService.isTokenSignatureValid(
                        new BearerAccessToken(signedAccessToken.serialize()).getValue()));
    }

    @Test
    void shouldSuccessfullyValidateNewV2RsaSignedAccessToken() throws JOSEException {
        var rsaKey = generateCustomRsaKeyPair(KEY_ID);
        var newRSAKey = generateCustomRsaKeyPair(NEW_V2_KEY_ID);
        var newRSASigner = new RSASSASigner(newRSAKey);

        when(configurationService.isRsaSigningAvailable()).thenReturn(true);
        when(jwksService.getPublicTokenRsaJwkWithOpaqueId()).thenReturn(rsaKey);
        when(jwksService.getNextPublicTokenRsaJwkWithOpaqueIdV2()).thenReturn(newRSAKey);

        SignedJWT signedAccessToken = createCustomSignedAccessToken(newRSASigner, NEW_V2_KEY_ID);
        assertTrue(
                tokenValidationService.isTokenSignatureValid(
                        new BearerAccessToken(signedAccessToken.serialize()).getValue()));
    }

    // QualityGateRegressionTest
    @Test
    void shouldFailToValidateRsaKeyAccessTokenIfKeyIdInvalid() throws JOSEException {
        var wrongRSAKey = generateCustomRsaKeyPair(FAILED_KEY_ID);
        var rsaKey = generateCustomRsaKeyPair(KEY_ID);
        var newRSAKey = generateCustomRsaKeyPair(NEW_V2_KEY_ID);
        var rsaSigner = new RSASSASigner(wrongRSAKey);

        when(configurationService.isRsaSigningAvailable()).thenReturn(true);
        when(jwksService.getPublicTokenRsaJwkWithOpaqueId()).thenReturn(rsaKey);
        when(jwksService.getNextPublicTokenRsaJwkWithOpaqueIdV2()).thenReturn(newRSAKey);

        SignedJWT signedAccessToken = createCustomSignedAccessToken(rsaSigner, FAILED_KEY_ID);
        assertFalse(
                tokenValidationService.isTokenSignatureValid(
                        new BearerAccessToken(signedAccessToken.serialize()).getValue()));
    }

    @Nested
    class ReauthJourneys {
        @Test
        void shouldSuccessfullyValidateReauthIDToken() {
            Date expiryDate = NowHelper.nowPlus(2, ChronoUnit.MINUTES);

            when(configurationService.isPublishOldExternalTokenSigningKeysEnabled())
                    .thenReturn(true);

            SignedJWT signedIdToken = createSignedIdToken(expiryDate);
            assertTrue(
                    tokenValidationService.isReauthTokenSignatureValid(signedIdToken.serialize()));
        }

        @Test
        void shouldNotFailSignatureValidationIfReauthIDTokenHasExpired() {
            Date expiryDate = NowHelper.nowMinus(2, ChronoUnit.MINUTES);

            when(configurationService.isPublishOldExternalTokenSigningKeysEnabled())
                    .thenReturn(true);

            SignedJWT signedIdToken = createSignedIdToken(expiryDate);
            assertTrue(
                    tokenValidationService.isReauthTokenSignatureValid(signedIdToken.serialize()));
        }

        @Test
        void shouldSuccessfullyValidateNewECKeyV2ReauthIDToken() {
            Date expiryDate = NowHelper.nowPlus(2, ChronoUnit.MINUTES);

            SignedJWT signedIdToken = createSignedIdTokenWithV2Key(expiryDate);
            assertTrue(
                    tokenValidationService.isReauthTokenSignatureValid(
                            new BearerAccessToken(signedIdToken.serialize()).getValue()));
        }

        @Test
        void
                shouldSuccessfullyValidateReauthIDTokenWithOldKeyWhenKeyIdMatchesAndOldKeyIsPublished() {
            Date expiryDate = NowHelper.nowPlus(2, ChronoUnit.MINUTES);

            when(configurationService.isPublishOldExternalTokenSigningKeysEnabled())
                    .thenReturn(true);

            SignedJWT signedIdToken = createSignedIdToken(expiryDate);
            assertTrue(
                    tokenValidationService.isReauthTokenSignatureValid(
                            new BearerAccessToken(signedIdToken.serialize()).getValue()));
        }

        @Test
        void shouldFailToValidateECKeyReauthIDTokenIfKeyIdInvalid() {
            Date expiryDate = NowHelper.nowPlus(2, ChronoUnit.MINUTES);
            var failedECKey = generateCustomECKeyPair(FAILED_KEY_ID);

            SignedJWT signedIdToken = createCustomSignedIdToken(expiryDate, failedECKey);
            assertFalse(
                    tokenValidationService.isReauthTokenSignatureValid(
                            new BearerAccessToken(signedIdToken.serialize()).getValue()));
        }

        @Test
        void
                shouldSuccessfullyValidateOldStoredECKeyReauthIDTokenWhenKeyIdMatchesAndStoredKeyEnabled() {
            Date expiryDate = NowHelper.nowPlus(2, ChronoUnit.MINUTES);
            var oldStoredECKey = generateCustomECKeyPair(OLD_STORED_KEY_ID);

            when(jwksService.getStoredOldPublicTokenJwksWithOpaqueId())
                    .thenReturn(new ArrayList<ECKey>(Arrays.asList(oldStoredECKey.toECKey())));
            when(configurationService.isUseStoredOldIdTokenPublicKeysEnabled()).thenReturn(true);

            SignedJWT signedIdToken = createCustomSignedIdToken(expiryDate, oldStoredECKey);
            assertTrue(
                    tokenValidationService.isReauthTokenSignatureValid(
                            new BearerAccessToken(signedIdToken.serialize()).getValue()));
        }

        @Test
        void
                shouldSuccessfullyValidateOldStoredECKeyReauthIDTokenWhenKeyIdMatchesAndStoredKeyDisabledAndOldKeyIsNotPublished() {
            Date expiryDate = NowHelper.nowPlus(2, ChronoUnit.MINUTES);
            var oldStoredECKey = generateCustomECKeyPair(OLD_STORED_KEY_ID);

            when(jwksService.getStoredOldPublicTokenJwksWithOpaqueId())
                    .thenReturn(new ArrayList<ECKey>(Arrays.asList(oldStoredECKey.toECKey())));
            when(configurationService.isUseStoredOldIdTokenPublicKeysEnabled()).thenReturn(false);
            when(configurationService.isPublishOldExternalTokenSigningKeysEnabled())
                    .thenReturn(false);

            SignedJWT signedIdToken = createCustomSignedIdToken(expiryDate, oldStoredECKey);
            assertTrue(
                    tokenValidationService.isReauthTokenSignatureValid(
                            new BearerAccessToken(signedIdToken.serialize()).getValue()));
        }

        @Test
        void shouldFailToValidateECKeyReauthIDTokenIfOldStoredPublicKeyIdInvalid() {
            Date expiryDate = NowHelper.nowPlus(2, ChronoUnit.MINUTES);
            var oldStoredECKey = generateCustomECKeyPair(OLD_STORED_KEY_ID);
            var failedECKey = generateCustomECKeyPair(FAILED_KEY_ID);

            when(jwksService.getStoredOldPublicTokenJwksWithOpaqueId())
                    .thenReturn(new ArrayList<ECKey>(Arrays.asList(oldStoredECKey.toECKey())));
            when(configurationService.isUseStoredOldIdTokenPublicKeysEnabled()).thenReturn(true);

            SignedJWT signedIdToken = createCustomSignedIdToken(expiryDate, failedECKey);
            assertFalse(
                    tokenValidationService.isReauthTokenSignatureValid(
                            new BearerAccessToken(signedIdToken.serialize()).getValue()));
        }

        @Test
        void shouldFailToValidateECKeyReauthIDTokenIfNoOldStoredPublicKey() {
            Date expiryDate = NowHelper.nowPlus(2, ChronoUnit.MINUTES);
            when(jwksService.getStoredOldPublicTokenJwksWithOpaqueId())
                    .thenReturn(new ArrayList<>());
            when(configurationService.isUseStoredOldIdTokenPublicKeysEnabled()).thenReturn(true);

            SignedJWT signedIdToken = createSignedIdToken(expiryDate);
            assertFalse(
                    tokenValidationService.isReauthTokenSignatureValid(
                            new BearerAccessToken(signedIdToken.serialize()).getValue()));
        }
    }

    @Test
    void shouldSuccessfullyValidateRefreshToken() {
        Date expiryDate = NowHelper.nowPlus(2, ChronoUnit.MINUTES);

        SignedJWT signedAccessToken = createSignedRefreshTokenWithExpiry(expiryDate);
        assertTrue(
                tokenValidationService.validateRefreshTokenSignatureAndExpiry(
                        new RefreshToken(signedAccessToken.serialize())));
    }

    // QualityGateRegressionTest
    @Test
    void shouldFailToValidateRefreshTokenIfExpired() {
        Date expiryDate = NowHelper.nowMinus(2, ChronoUnit.MINUTES);

        SignedJWT signedAccessToken = createSignedRefreshTokenWithExpiry(expiryDate);
        assertFalse(
                tokenValidationService.validateRefreshTokenSignatureAndExpiry(
                        new RefreshToken(signedAccessToken.serialize())));
    }

    // QualityGateRegressionTest
    @Test
    void shouldSuccessfullyValidateRefreshTokenScopes() {
        List<String> clientScopes = List.of("openid", "email", "phone", "offline_access");
        assertTrue(tokenValidationService.validateRefreshTokenScopes(clientScopes, REFRESH_SCOPES));
    }

    // QualityGateRegressionTest
    @Test
    void shouldFailToValidateRefreshTokenScopesWhenMissingOfflineAccess() {
        List<String> clientScopes = List.of("openid", "email", "phone", "offline_access");
        List<String> refreshScopes = List.of("openid", "email", "phone");
        assertFalse(tokenValidationService.validateRefreshTokenScopes(clientScopes, refreshScopes));
    }

    // QualityGateRegressionTest
    @Test
    void shouldFailToValidateRefreshTokenScopesWhenClientScopesDoNotContainAllRefreshTokenScopes() {
        List<String> clientScopes = List.of("openid", "phone", "offline_access");
        assertFalse(
                tokenValidationService.validateRefreshTokenScopes(clientScopes, REFRESH_SCOPES));
    }

    private RSAKey generateCustomRsaKeyPair(String keyId) {
        try {
            return new RSAKeyGenerator(2048).keyID(keyId).generate();
        } catch (JOSEException e) {
            throw new RuntimeException();
        }
    }

    private ECKey generateCustomECKeyPair(String keyId) {
        try {
            return new ECKeyGenerator(Curve.P_256).keyID(keyId).generate();
        } catch (JOSEException e) {
            throw new RuntimeException();
        }
    }

    private ECKey generateECKeyPair() {
        return generateCustomECKeyPair(KEY_ID);
    }

    private SignedJWT createSignedIdToken(Date expiryDate) {
        return TokenGeneratorHelper.generateIDToken(
                CLIENT_ID, SUBJECT, BASE_URL, ecJWK, expiryDate);
    }

    private SignedJWT createSignedIdTokenWithV2Key(Date expiryDate) {
        return TokenGeneratorHelper.generateIDToken(
                CLIENT_ID, SUBJECT, BASE_URL, newV2ECJWK, expiryDate);
    }

    private SignedJWT createCustomSignedIdToken(Date expiryDate, ECKey ecKey) {
        return TokenGeneratorHelper.generateIDToken(
                CLIENT_ID, SUBJECT, BASE_URL, ecKey, expiryDate);
    }

    private SignedJWT createSignedAccessTokenWithV2Signer() {
        return createCustomSignedAccessToken(newV2Signer, NEW_V2_KEY_ID);
    }

    private SignedJWT createCustomSignedAccessToken(JWSSigner signer, String keyId) {
        return TokenGeneratorHelper.generateSignedToken(
                CLIENT_ID, BASE_URL, SCOPES, signer, SUBJECT, keyId);
    }

    private SignedJWT createSignedRefreshTokenWithExpiry(Date expiryDate) {
        return TokenGeneratorHelper.generateSignedToken(
                CLIENT_ID,
                BASE_URL,
                REFRESH_SCOPES,
                newV2Signer,
                SUBJECT,
                NEW_V2_KEY_ID,
                expiryDate);
    }
}
