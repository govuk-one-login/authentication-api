package uk.gov.di.authentication.shared.services;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.sharedtest.helper.TokenGeneratorHelper;
import uk.gov.di.authentication.sharedtest.logging.CaptureLoggingExtension;

import java.net.MalformedURLException;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.sharedtest.logging.LogEventMatcher.withMessageContaining;

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
    private JWSSigner signer;
    private ECKey ecJWK;

    @RegisterExtension
    public final CaptureLoggingExtension logging =
            new CaptureLoggingExtension(TokenValidationService.class);

    @BeforeEach
    void setUp() throws JOSEException, MalformedURLException {
        ecJWK = generateECKeyPair();
        signer = new ECDSASigner(ecJWK);
        when(jwksService.getPublicTokenJwkWithOpaqueId(any())).thenReturn(ecJWK.toPublicJWK());
        when(configurationService.getEnvironment()).thenReturn("dev");
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
    void shouldSuccessfullyValidateTestAccessToken() throws JOSEException {
        ECKey testEcJWK = generateECKeyPair();
        JWSSigner signer = new ECDSASigner(testEcJWK);
        SignedJWT signedTestAccessToken = createSignedAccessToken(signer);

        when(configurationService.isTestSigningKeyEnabled()).thenReturn(true);
        when(jwksService.getPublicTestTokenJwkWithOpaqueId()).thenReturn(testEcJWK.toPublicJWK());

        assertTrue(
                tokenValidationService.validateAccessTokenSignature(
                        new BearerAccessToken(signedTestAccessToken.serialize())));
        assertThat(
                logging.events(),
                hasItem(withMessageContaining("Token signature validated using test key")));
    }

    @Test
    void shouldSuccessfullyValidateRealAccessTokenWhenTestAccessTokenExists() {
        ECKey testEcJWK = generateECKeyPair();
        SignedJWT signedAccessToken = createSignedAccessToken(signer);

        when(configurationService.isTestSigningKeyEnabled()).thenReturn(true);
        when(jwksService.getPublicTestTokenJwkWithOpaqueId()).thenReturn(testEcJWK.toPublicJWK());

        assertTrue(
                tokenValidationService.validateAccessTokenSignature(
                        new BearerAccessToken(signedAccessToken.serialize())));
        assertThat(
                logging.events(),
                not(hasItem(withMessageContaining("Token signature validated using test key"))));
    }

    @Test
    void shouldFailToValidateTokenSignedWithDifferentKeyWhenTestAccessTokenExists()
            throws JOSEException {
        ECKey testEcJWK = generateECKeyPair();

        ECKey someOtherJwk = generateECKeyPair();
        JWSSigner signer = new ECDSASigner(someOtherJwk);
        SignedJWT signedAccessTokenWithDifferentKey = createSignedAccessToken(signer);

        when(configurationService.isTestSigningKeyEnabled()).thenReturn(true);
        when(jwksService.getPublicTestTokenJwkWithOpaqueId()).thenReturn(testEcJWK.toPublicJWK());

        assertFalse(
                tokenValidationService.validateAccessTokenSignature(
                        new BearerAccessToken(signedAccessTokenWithDifferentKey.serialize())));
    }

    @Test
    void shouldSuccessfullyValidateAccessToken() {
        SignedJWT signedAccessToken = createSignedAccessToken(signer);

        assertTrue(
                tokenValidationService.validateAccessTokenSignature(
                        new BearerAccessToken(signedAccessToken.serialize())));
    }

    @Test
    void shouldSuccessfullyValidateRsaSignedAccessToken()
            throws JOSEException, MalformedURLException {
        var rsaKey = new RSAKeyGenerator(2048).generate();
        var rsaSigner = new RSASSASigner(rsaKey);

        when(configurationService.isRsaSigningAvailable()).thenReturn(true);
        when(jwksService.getPublicTokenRsaJwkWithOpaqueId(any())).thenReturn(rsaKey);

        SignedJWT signedAccessToken = createSignedAccessToken(rsaSigner);
        assertTrue(
                tokenValidationService.validateAccessTokenSignature(
                        new BearerAccessToken(signedAccessToken.serialize())));
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
