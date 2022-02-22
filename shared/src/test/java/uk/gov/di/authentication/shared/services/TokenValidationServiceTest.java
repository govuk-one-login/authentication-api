package uk.gov.di.authentication.shared.services;

import com.amazonaws.services.kms.model.GetPublicKeyRequest;
import com.amazonaws.services.kms.model.GetPublicKeyResult;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.sharedtest.helper.TokenGeneratorHelper;

import java.nio.ByteBuffer;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class TokenValidationServiceTest {

    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final KmsConnectionService kmsConnectionService = mock(KmsConnectionService.class);
    private final TokenValidationService tokenValidationService =
            new TokenValidationService(configurationService, kmsConnectionService);
    private static final Subject SUBJECT = new Subject("some-subject");
    private static final List<String> SCOPES = List.of("openid", "email", "phone");
    private static final List<String> REFRESH_SCOPES = List.of("openid", "email", "offline_access");
    private static final String CLIENT_ID = "client-id";
    private static final String BASE_URL = "http://example.com";
    private static final String KEY_ID = "14342354354353";
    private JWSSigner signer;
    private ECKey ecJWK;

    @BeforeEach
    void setUp() throws JOSEException {
        Optional<String> baseUrl = Optional.of(BASE_URL);
        when(configurationService.getBaseURL()).thenReturn(baseUrl);
        ecJWK = generateECKeyPair();
        signer = new ECDSASigner(ecJWK);
        when(configurationService.getTokenSigningKeyAlias()).thenReturn(KEY_ID);
        GetPublicKeyResult getPublicKeyResult = new GetPublicKeyResult();
        getPublicKeyResult.setKeyUsage("SIGN_VERIFY");
        getPublicKeyResult.setKeyId(KEY_ID);
        getPublicKeyResult.setSigningAlgorithms(
                Collections.singletonList(JWSAlgorithm.ES256.getName()));
        getPublicKeyResult.setPublicKey(
                ByteBuffer.wrap(ecJWK.toPublicJWK().toECPublicKey().getEncoded()));
        when(kmsConnectionService.getPublicKey(any(GetPublicKeyRequest.class)))
                .thenReturn(getPublicKeyResult);
    }

    @Test
    void shouldSuccessfullyValidateIDToken() {
        LocalDateTime localDateTime = LocalDateTime.now().plusMinutes(2);
        Date expiryDate = Date.from(localDateTime.atZone(ZoneId.of("UTC")).toInstant());
        SignedJWT signedIdToken = createSignedIdToken(expiryDate);
        assertTrue(tokenValidationService.isTokenSignatureValid(signedIdToken.serialize()));
    }

    @Test
    void shouldNotFailSignatureValidationIfIdTokenHasExpired() {
        LocalDateTime localDateTime = LocalDateTime.now().minusMinutes(2);
        Date expiryDate = Date.from(localDateTime.atZone(ZoneId.systemDefault()).toInstant());
        SignedJWT signedIdToken = createSignedIdToken(expiryDate);
        assertTrue(tokenValidationService.isTokenSignatureValid(signedIdToken.serialize()));
    }

    @Test
    void shouldSuccessfullyValidateAccessToken() {
        SignedJWT signedAccessToken = createSignedAccessToken(signer);
        assertTrue(
                tokenValidationService.validateAccessTokenSignature(
                        new BearerAccessToken(signedAccessToken.serialize())));
    }

    @Test
    void shouldSuccessfullyValidateRefreshToken() {
        LocalDateTime localDateTime = LocalDateTime.now().plusMinutes(2);
        Date expiryDate = Date.from(localDateTime.atZone(ZoneId.of("UTC")).toInstant());

        SignedJWT signedAccessToken = createSignedRefreshTokenWithExpiry(signer, expiryDate);
        assertTrue(
                tokenValidationService.validateRefreshTokenSignatureAndExpiry(
                        new RefreshToken(signedAccessToken.serialize())));
    }

    @Test
    void shouldFailToValidateRefreshTokenIfExpired() {
        LocalDateTime localDateTime = LocalDateTime.now().minusMinutes(2);
        Date expiryDate = Date.from(localDateTime.atZone(ZoneId.of("UTC")).toInstant());

        SignedJWT signedAccessToken = createSignedRefreshTokenWithExpiry(signer, expiryDate);
        assertFalse(
                tokenValidationService.validateRefreshTokenSignatureAndExpiry(
                        new RefreshToken(signedAccessToken.serialize())));
    }

    @Test
    void shouldRetrievePublicKeyfromKmsAndParseToJwk() {
        String keyId = "3423543t5435345";
        byte[] publicKey =
                Base64.getDecoder()
                        .decode(
                                "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEpRm+QZsh2IkUWcqXUhBI9ulOzO8dz0Z8HIS6m77tI4eWoZgKYUcbByshDtN4gWPql7E5mN4uCLsg5+6SDXlQcA==");
        when(configurationService.getTokenSigningKeyAlias()).thenReturn(keyId);
        GetPublicKeyResult getPublicKeyResult = new GetPublicKeyResult();
        getPublicKeyResult.setKeyUsage("SIGN_VERIFY");
        getPublicKeyResult.setKeyId(keyId);
        getPublicKeyResult.setSigningAlgorithms(
                Collections.singletonList(JWSAlgorithm.ES256.getName()));
        getPublicKeyResult.setPublicKey(ByteBuffer.wrap(publicKey));
        when(kmsConnectionService.getPublicKey(any(GetPublicKeyRequest.class)))
                .thenReturn(getPublicKeyResult);
        JWK publicKeyJwk = tokenValidationService.getPublicJwk();
        assertEquals(publicKeyJwk.getKeyID(), keyId);
        assertEquals(publicKeyJwk.getAlgorithm(), JWSAlgorithm.ES256);
        assertEquals(publicKeyJwk.getKeyUse(), KeyUse.SIGNATURE);
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

    private ECKey generateECKeyPair() {
        try {
            return new ECKeyGenerator(Curve.P_256).keyID(KEY_ID).generate();
        } catch (JOSEException e) {
            throw new RuntimeException();
        }
    }

    private SignedJWT createSignedIdToken(Date expiryDate) {
        return TokenGeneratorHelper.generateIDToken(
                CLIENT_ID, SUBJECT, BASE_URL, ecJWK, expiryDate);
    }

    private SignedJWT createSignedAccessToken(JWSSigner signer) {

        return TokenGeneratorHelper.generateSignedToken(
                CLIENT_ID, BASE_URL, SCOPES, signer, SUBJECT, KEY_ID);
    }

    private SignedJWT createSignedRefreshTokenWithExpiry(JWSSigner signer, Date expiryDate) {
        return TokenGeneratorHelper.generateSignedToken(
                CLIENT_ID, BASE_URL, REFRESH_SCOPES, signer, SUBJECT, KEY_ID, expiryDate);
    }
}
