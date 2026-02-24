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
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

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
    private static final String NEW_KEY_ID = "14342354354354";
    private static final String NEW_KEY_ID_V2 = "14342354354359V2";
    private static final String FAILED_KEY_ID = "14342354354355";
    private JWSSigner signer;
    private ECKey ecJWK;

    @BeforeEach
    void setUp() throws JOSEException {
        ecJWK = generateECKeyPair();
        signer = new ECDSASigner(ecJWK);
        when(jwksService.getPublicTokenJwkWithOpaqueId()).thenReturn(ecJWK.toPublicJWK());
        when(configurationService.isPublishNextExternalTokenSigningKeysEnabled()).thenReturn(false);
    }

    @Test
    void shouldSuccessfullyValidateIDToken() {
        Date expiryDate = NowHelper.nowPlus(2, ChronoUnit.MINUTES);
        SignedJWT signedIdToken = createSignedIdToken(expiryDate);
        assertTrue(tokenValidationService.isTokenSignatureValid(signedIdToken.serialize()));
    }

    @Test
    void shouldNotFailSignatureValidationIfIdTokenHasExpired() {
        Date expiryDate = NowHelper.nowMinus(2, ChronoUnit.MINUTES);
        SignedJWT signedIdToken = createSignedIdToken(expiryDate);
        assertTrue(tokenValidationService.isTokenSignatureValid(signedIdToken.serialize()));
    }

    @Test
    void shouldSuccessfullyValidateAccessToken() {
        SignedJWT signedAccessToken = createSignedAccessToken(signer);
        assertTrue(
                tokenValidationService.isTokenSignatureValid(
                        new BearerAccessToken(signedAccessToken.serialize()).getValue()));
    }

    @Test
    void shouldSuccessfullyValidateNewECKeyAccessToken() throws JOSEException {
        var newECKey = generateCustomECKeyPair(NEW_KEY_ID);
        var ecSigner = new ECDSASigner(newECKey);

        when(jwksService.getNextPublicTokenJwkWithOpaqueId()).thenReturn(newECKey);
        when(configurationService.isPublishNextExternalTokenSigningKeysEnabled()).thenReturn(true);

        SignedJWT signedAccessToken = createCustomSignedAccessToken(ecSigner, NEW_KEY_ID);
        assertTrue(
                tokenValidationService.isTokenSignatureValid(
                        new BearerAccessToken(signedAccessToken.serialize()).getValue()));
    }

    @Test
    void shouldFailToValidateECKeyAccessTokenIfNeitherKeyId() throws JOSEException {
        var newECKey = generateCustomECKeyPair(NEW_KEY_ID);
        var failedECKey = generateCustomECKeyPair(FAILED_KEY_ID);
        var ecSigner = new ECDSASigner(failedECKey);

        when(jwksService.getNextPublicTokenJwkWithOpaqueId()).thenReturn(newECKey);
        when(configurationService.isPublishNextExternalTokenSigningKeysEnabled()).thenReturn(true);

        SignedJWT signedAccessToken = createCustomSignedAccessToken(ecSigner, FAILED_KEY_ID);
        assertFalse(
                tokenValidationService.isTokenSignatureValid(
                        new BearerAccessToken(signedAccessToken.serialize()).getValue()));
    }

    @Test
    void shouldSuccessfullyValidateRsaSignedAccessToken() throws JOSEException {
        var rsaKey = generateCustomRsaKeyPair(KEY_ID);
        var rsaSigner = new RSASSASigner(rsaKey);

        when(configurationService.isRsaSigningAvailable()).thenReturn(true);
        when(jwksService.getPublicTokenRsaJwkWithOpaqueId()).thenReturn(rsaKey);

        SignedJWT signedAccessToken = createSignedAccessToken(rsaSigner);
        assertTrue(
                tokenValidationService.isTokenSignatureValid(
                        new BearerAccessToken(signedAccessToken.serialize()).getValue()));
    }

    @Test
    void shouldSuccessfullyValidateNewRsaSignedAccessToken() throws JOSEException {
        var rsaKey = generateCustomRsaKeyPair(KEY_ID);
        var newRSAKey = generateCustomRsaKeyPair(NEW_KEY_ID);
        var newRSASigner = new RSASSASigner(newRSAKey);

        when(configurationService.isRsaSigningAvailable()).thenReturn(true);
        when(configurationService.isPublishNextExternalTokenSigningKeysEnabled()).thenReturn(true);
        when(jwksService.getPublicTokenRsaJwkWithOpaqueId()).thenReturn(rsaKey);
        when(jwksService.getNextPublicTokenRsaJwkWithOpaqueId()).thenReturn(newRSAKey);

        SignedJWT signedAccessToken = createCustomSignedAccessToken(newRSASigner, NEW_KEY_ID);
        assertTrue(
                tokenValidationService.isTokenSignatureValid(
                        new BearerAccessToken(signedAccessToken.serialize()).getValue()));
    }

    @Test
    void shouldFailToValidateRsaKeyAccessTokenIfNeitherKeyId() throws JOSEException {
        var wrongRSAKey = new RSAKeyGenerator(2048).generate();
        var rsaSigner = new RSASSASigner(wrongRSAKey);
        var rsaKey = generateCustomRsaKeyPair(KEY_ID);
        var newRSAKey = generateCustomRsaKeyPair(NEW_KEY_ID);

        when(configurationService.isRsaSigningAvailable()).thenReturn(true);
        when(configurationService.isPublishNextExternalTokenSigningKeysEnabled()).thenReturn(true);
        when(jwksService.getPublicTokenRsaJwkWithOpaqueId()).thenReturn(rsaKey);
        when(jwksService.getNextPublicTokenRsaJwkWithOpaqueId()).thenReturn(newRSAKey);

        SignedJWT signedAccessToken = createCustomSignedAccessToken(rsaSigner, FAILED_KEY_ID);
        assertFalse(
                tokenValidationService.isTokenSignatureValid(
                        new BearerAccessToken(signedAccessToken.serialize()).getValue()));
    }

    @Nested
    class RSAKeyRotationV2 {
        @Test
        void shouldValidateTokenSignedWithV2NewKeyWhenFlagEnabled() throws JOSEException {
            var rsaKey = generateCustomRsaKeyPair(KEY_ID);
            var nextKeyV1 = generateCustomRsaKeyPair(NEW_KEY_ID);
            var nextKeyV2 = generateCustomRsaKeyPair(NEW_KEY_ID_V2);
            var newKeyV2RSASigner = new RSASSASigner(nextKeyV2);

            when(configurationService.isRsaSigningAvailable()).thenReturn(true);
            when(configurationService.isPublishNextExternalTokenSigningKeysEnabledV2())
                    .thenReturn(true);
            when(jwksService.getPublicTokenRsaJwkWithOpaqueId()).thenReturn(rsaKey);
            when(jwksService.getNextPublicTokenRsaJwkWithOpaqueId()).thenReturn(nextKeyV1);
            when(jwksService.getNextPublicTokenRsaJwkWithOpaqueIdV2()).thenReturn(nextKeyV2);

            SignedJWT signedAccessToken =
                    createCustomSignedAccessToken(newKeyV2RSASigner, NEW_KEY_ID_V2);
            assertTrue(
                    tokenValidationService.isTokenSignatureValid(
                            new BearerAccessToken(signedAccessToken.serialize()).getValue()));
        }

        @Test
        void shouldValidateTokenSignedWithNewKeyV1KeyV2KeyFlagEnabled() throws JOSEException {
            var previousKey = generateCustomRsaKeyPair(KEY_ID);
            var nextKeyV1 = generateCustomRsaKeyPair(NEW_KEY_ID);
            var nextKeyV2 = generateCustomRsaKeyPair(NEW_KEY_ID_V2);
            var nextKeyV1Signer = new RSASSASigner(previousKey);

            when(configurationService.isRsaSigningAvailable()).thenReturn(true);
            when(configurationService.isPublishNextExternalTokenSigningKeysEnabledV2())
                    .thenReturn(true);
            when(jwksService.getPublicTokenRsaJwkWithOpaqueId()).thenReturn(previousKey);
            when(jwksService.getNextPublicTokenRsaJwkWithOpaqueId()).thenReturn(nextKeyV1);
            when(jwksService.getNextPublicTokenRsaJwkWithOpaqueIdV2()).thenReturn(nextKeyV2);

            SignedJWT signedAccessToken = createCustomSignedAccessToken(nextKeyV1Signer, KEY_ID);
            assertTrue(
                    tokenValidationService.isTokenSignatureValid(
                            new BearerAccessToken(signedAccessToken.serialize()).getValue()));
        }

        @Test
        void shouldValidateTokenSignedWithOriginalKeyWhenV2KeyFlagEnabled() throws JOSEException {
            var previousKey = generateCustomRsaKeyPair(KEY_ID);
            var nextKeyV1 = generateCustomRsaKeyPair(NEW_KEY_ID);
            var nextKeyV2 = generateCustomRsaKeyPair(NEW_KEY_ID_V2);
            var previousKeySigner = new RSASSASigner(previousKey);

            when(configurationService.isRsaSigningAvailable()).thenReturn(true);
            when(configurationService.isPublishNextExternalTokenSigningKeysEnabledV2())
                    .thenReturn(true);
            when(jwksService.getPublicTokenRsaJwkWithOpaqueId()).thenReturn(previousKey);
            when(jwksService.getNextPublicTokenRsaJwkWithOpaqueId()).thenReturn(nextKeyV1);
            when(jwksService.getNextPublicTokenRsaJwkWithOpaqueIdV2()).thenReturn(nextKeyV2);

            SignedJWT signedAccessToken = createCustomSignedAccessToken(previousKeySigner, KEY_ID);
            assertTrue(
                    tokenValidationService.isTokenSignatureValid(
                            new BearerAccessToken(signedAccessToken.serialize()).getValue()));
        }

        @Test
        void shouldFailToValidateForUnknownKey() throws JOSEException {
            var unknownKeyId = "unknown-key-id";
            var previousKey = generateCustomRsaKeyPair(KEY_ID);
            var nextKeyV1 = generateCustomRsaKeyPair(NEW_KEY_ID);
            var nextKeyV2 = generateCustomRsaKeyPair(NEW_KEY_ID_V2);
            var unknownKey = generateCustomRsaKeyPair(unknownKeyId);

            var unknownSigner = new RSASSASigner(unknownKey);

            when(configurationService.isRsaSigningAvailable()).thenReturn(true);
            when(configurationService.isPublishNextExternalTokenSigningKeysEnabledV2())
                    .thenReturn(true);
            when(jwksService.getPublicTokenRsaJwkWithOpaqueId()).thenReturn(previousKey);
            when(jwksService.getNextPublicTokenRsaJwkWithOpaqueId()).thenReturn(nextKeyV1);
            when(jwksService.getNextPublicTokenRsaJwkWithOpaqueIdV2()).thenReturn(nextKeyV2);

            SignedJWT signedAccessToken =
                    createCustomSignedAccessToken(unknownSigner, unknownKeyId);
            assertFalse(
                    tokenValidationService.isTokenSignatureValid(
                            new BearerAccessToken(signedAccessToken.serialize()).getValue()));
        }
    }

    @Nested
    class ECKeyRotationV2 {
        @Test
        void shouldValidateTokenSignedWithV2NewKeyWhenFlagEnabled() throws JOSEException {
            var previousECKey = generateCustomECKeyPair(KEY_ID);
            var newECKeyV1 = generateCustomECKeyPair(NEW_KEY_ID);
            var newEcKeyV2 = generateCustomECKeyPair(NEW_KEY_ID_V2);

            var ecSignerNewV2Key = new ECDSASigner(newEcKeyV2);

            when(configurationService.isPublishNextExternalTokenSigningKeysEnabledV2())
                    .thenReturn(true);
            when(jwksService.getPublicTokenJwkWithOpaqueId()).thenReturn(previousECKey);
            when(jwksService.getNextPublicTokenJwkWithOpaqueId()).thenReturn(newECKeyV1);
            when(jwksService.getNextPublicTokenJwkWithOpaqueIdV2()).thenReturn(newEcKeyV2);

            SignedJWT signedAccessToken =
                    createCustomSignedAccessToken(ecSignerNewV2Key, NEW_KEY_ID_V2);
            assertTrue(
                    tokenValidationService.isTokenSignatureValid(
                            new BearerAccessToken(signedAccessToken.serialize()).getValue()));
        }

        @Test
        void shouldValidateTokenSignedWithNewKeyV1KeyWhenV2FlagEnabled() throws JOSEException {
            var previousECKey = generateCustomECKeyPair(KEY_ID);
            var newECKeyV1 = generateCustomECKeyPair(NEW_KEY_ID);
            var newEcKeyV2 = generateCustomECKeyPair(NEW_KEY_ID_V2);

            var nextKeyV1Signer = new ECDSASigner(newECKeyV1);

            when(configurationService.isPublishNextExternalTokenSigningKeysEnabledV2())
                    .thenReturn(true);
            when(jwksService.getPublicTokenJwkWithOpaqueId()).thenReturn(previousECKey);
            when(jwksService.getNextPublicTokenJwkWithOpaqueId()).thenReturn(newECKeyV1);
            when(jwksService.getNextPublicTokenJwkWithOpaqueIdV2()).thenReturn(newEcKeyV2);

            SignedJWT signedAccessToken =
                    createCustomSignedAccessToken(nextKeyV1Signer, NEW_KEY_ID);
            assertTrue(
                    tokenValidationService.isTokenSignatureValid(
                            new BearerAccessToken(signedAccessToken.serialize()).getValue()));
        }

        @Test
        void shouldValidateTokenSignedWithOriginalKeyWhenV2KeyFlagEnabled() throws JOSEException {
            var previousECKey = generateCustomECKeyPair(KEY_ID);
            var newECKeyV1 = generateCustomECKeyPair(NEW_KEY_ID);
            var newEcKeyV2 = generateCustomECKeyPair(NEW_KEY_ID_V2);

            var previousKeySigner = new ECDSASigner(previousECKey);

            when(configurationService.isPublishNextExternalTokenSigningKeysEnabledV2())
                    .thenReturn(true);
            when(jwksService.getPublicTokenJwkWithOpaqueId()).thenReturn(previousECKey);
            when(jwksService.getNextPublicTokenJwkWithOpaqueId()).thenReturn(newECKeyV1);
            when(jwksService.getNextPublicTokenJwkWithOpaqueIdV2()).thenReturn(newEcKeyV2);

            SignedJWT signedAccessToken = createCustomSignedAccessToken(previousKeySigner, KEY_ID);
            assertTrue(
                    tokenValidationService.isTokenSignatureValid(
                            new BearerAccessToken(signedAccessToken.serialize()).getValue()));
        }

        @Test
        void shouldFailToValidateForUnknownKey() throws JOSEException {
            var unknownKeyId = "unknown-key-id";
            var unknownKey = generateCustomECKeyPair(unknownKeyId);
            var previousECKey = generateCustomECKeyPair(KEY_ID);
            var newECKeyV1 = generateCustomECKeyPair(NEW_KEY_ID);
            var newEcKeyV2 = generateCustomECKeyPair(NEW_KEY_ID_V2);

            var unknownSigner = new ECDSASigner(unknownKey);

            when(configurationService.isPublishNextExternalTokenSigningKeysEnabledV2())
                    .thenReturn(true);
            when(jwksService.getPublicTokenJwkWithOpaqueId()).thenReturn(previousECKey);
            when(jwksService.getNextPublicTokenJwkWithOpaqueId()).thenReturn(newECKeyV1);
            when(jwksService.getNextPublicTokenJwkWithOpaqueIdV2()).thenReturn(newEcKeyV2);

            SignedJWT signedAccessToken =
                    createCustomSignedAccessToken(unknownSigner, unknownKeyId);
            assertFalse(
                    tokenValidationService.isTokenSignatureValid(
                            new BearerAccessToken(signedAccessToken.serialize()).getValue()));
        }
    }

    @Test
    void shouldSuccessfullyValidateRefreshToken() {
        Date expiryDate = NowHelper.nowPlus(2, ChronoUnit.MINUTES);

        SignedJWT signedAccessToken = createSignedRefreshTokenWithExpiry(signer, expiryDate);
        assertTrue(
                tokenValidationService.validateRefreshTokenSignatureAndExpiry(
                        new RefreshToken(signedAccessToken.serialize())));
    }

    @Test
    void shouldFailToValidateRefreshTokenIfExpired() {
        Date expiryDate = NowHelper.nowMinus(2, ChronoUnit.MINUTES);

        SignedJWT signedAccessToken = createSignedRefreshTokenWithExpiry(signer, expiryDate);
        assertFalse(
                tokenValidationService.validateRefreshTokenSignatureAndExpiry(
                        new RefreshToken(signedAccessToken.serialize())));
    }

    @Test
    void shouldSuccessfullyValidateRefreshTokenScopes() {
        List<String> clientScopes = List.of("openid", "email", "phone", "offline_access");
        assertTrue(tokenValidationService.validateRefreshTokenScopes(clientScopes, REFRESH_SCOPES));
    }

    @Test
    void shouldFailToValidateRefreshTokenScopesWhenMissingOfflineAccess() {
        List<String> clientScopes = List.of("openid", "email", "phone", "offline_access");
        List<String> refreshScopes = List.of("openid", "email", "phone");
        assertFalse(tokenValidationService.validateRefreshTokenScopes(clientScopes, refreshScopes));
    }

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

    private SignedJWT createCustomSignedAccessToken(JWSSigner signer, String keyId) {

        return TokenGeneratorHelper.generateSignedToken(
                CLIENT_ID, BASE_URL, SCOPES, signer, SUBJECT, keyId);
    }

    private SignedJWT createSignedAccessToken(JWSSigner signer) {

        return createCustomSignedAccessToken(signer, KEY_ID);
    }

    private SignedJWT createSignedRefreshTokenWithExpiry(JWSSigner signer, Date expiryDate) {
        return TokenGeneratorHelper.generateSignedToken(
                CLIENT_ID, BASE_URL, REFRESH_SCOPES, signer, SUBJECT, KEY_ID, expiryDate);
    }
}
