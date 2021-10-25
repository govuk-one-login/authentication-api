package uk.gov.di.authentication.shared.services;

import com.amazonaws.services.kms.model.SignRequest;
import com.amazonaws.services.kms.model.SignResult;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.impl.ECDSA;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.auth.PrivateKeyJWT;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.oauth2.sdk.util.URLUtils;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.entity.AccessTokenStore;
import uk.gov.di.authentication.shared.entity.ClientConsent;
import uk.gov.di.authentication.shared.entity.CredentialTrustLevel;
import uk.gov.di.authentication.shared.entity.ValidScopes;
import uk.gov.di.authentication.shared.helpers.TokenGeneratorHelper;

import java.net.URI;
import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.text.ParseException;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class TokenServiceTest {

    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final KmsConnectionService kmsConnectionService = mock(KmsConnectionService.class);
    private final RedisConnectionService redisConnectionService =
            mock(RedisConnectionService.class);
    private final TokenService tokenService =
            new TokenService(configurationService, redisConnectionService, kmsConnectionService);
    private static final Subject PUBLIC_SUBJECT = new Subject("public-subject");
    private static final Subject INTERNAL_SUBJECT = new Subject("internal-subject");
    private static final Scope SCOPES =
            new Scope(OIDCScopeValue.OPENID, OIDCScopeValue.EMAIL, OIDCScopeValue.PHONE);
    private static final String VOT = CredentialTrustLevel.MEDIUM_LEVEL.getValue();
    private static final Scope SCOPES_OFFLINE_ACCESS =
            new Scope(
                    OIDCScopeValue.OPENID,
                    OIDCScopeValue.EMAIL,
                    OIDCScopeValue.PHONE,
                    OIDCScopeValue.OFFLINE_ACCESS);
    private static final String CLIENT_ID = "client-id";
    private static final String AUTH_CODE = new AuthorizationCode().toString();
    private static final String REDIRECT_URI = "http://localhost/redirect";
    private static final String BASE_URL = "http://example.com";
    private static final String KEY_ID = "14342354354353";
    private static final String REFRESH_TOKEN_PREFIX = "REFRESH_TOKEN:";
    private static final String ACCESS_TOKEN_PREFIX = "ACCESS_TOKEN:";

    @BeforeEach
    public void setUp() {
        Optional<String> baseUrl = Optional.of(BASE_URL);
        when(configurationService.getBaseURL()).thenReturn(baseUrl);
        when(configurationService.getAccessTokenExpiry()).thenReturn(300L);
        when(configurationService.getIDTokenExpiry()).thenReturn(120L);
        when(configurationService.getSessionExpiry()).thenReturn(300L);
    }

    @Test
    public void shouldGenerateTokenResponseWithRefreshToken()
            throws ParseException, JOSEException, JsonProcessingException {
        Nonce nonce = new Nonce();
        when(configurationService.getTokenSigningKeyAlias()).thenReturn(KEY_ID);
        createSignedIdToken();
        createSignedAccessToken();
        Map<String, Object> additionalTokenClaims = new HashMap<>();
        additionalTokenClaims.put("nonce", nonce);
        Set<String> claimsForListOfScopes =
                ValidScopes.getClaimsForListOfScopes(SCOPES_OFFLINE_ACCESS.toStringList());

        OIDCTokenResponse tokenResponse =
                tokenService.generateTokenResponse(
                        CLIENT_ID,
                        INTERNAL_SUBJECT,
                        SCOPES_OFFLINE_ACCESS,
                        additionalTokenClaims,
                        PUBLIC_SUBJECT,
                        VOT,
                        Collections.singletonList(
                                new ClientConsent(
                                        CLIENT_ID,
                                        claimsForListOfScopes,
                                        LocalDateTime.now(ZoneId.of("UTC")).toString())),
                        false);

        assertEquals(
                BASE_URL, tokenResponse.getOIDCTokens().getIDToken().getJWTClaimsSet().getIssuer());
        assertEquals(
                PUBLIC_SUBJECT.getValue(),
                tokenResponse.getOIDCTokens().getIDToken().getJWTClaimsSet().getClaim("sub"));
        assertNotNull(tokenResponse.getOIDCTokens().getRefreshToken());
        String accessTokenKey = ACCESS_TOKEN_PREFIX + CLIENT_ID + "." + PUBLIC_SUBJECT;
        AccessTokenStore accessTokenStore =
                new AccessTokenStore(
                        tokenResponse.getOIDCTokens().getAccessToken().getValue(),
                        INTERNAL_SUBJECT.getValue());
        verify(redisConnectionService)
                .saveWithExpiry(
                        accessTokenKey,
                        new ObjectMapper().writeValueAsString(accessTokenStore),
                        300L);
        String refreshTokenKey = REFRESH_TOKEN_PREFIX + CLIENT_ID + "." + PUBLIC_SUBJECT;
        AccessTokenStore refreshTokenStore =
                new AccessTokenStore(
                        tokenResponse.getOIDCTokens().getRefreshToken().getValue(),
                        INTERNAL_SUBJECT.getValue());
        verify(redisConnectionService)
                .saveWithExpiry(
                        refreshTokenKey,
                        new ObjectMapper().writeValueAsString(refreshTokenStore),
                        300L);
        assertEquals(
                nonce.getValue(),
                tokenResponse.getOIDCTokens().getIDToken().getJWTClaimsSet().getClaim("nonce"));
    }

    @Test
    public void shouldGenerateTokenResponseWithoutRefreshTokenWhenOfflineAccessScopeIsMissing()
            throws ParseException, JOSEException, JsonProcessingException {
        Nonce nonce = new Nonce();
        when(configurationService.getTokenSigningKeyAlias()).thenReturn(KEY_ID);
        when(configurationService.getAccessTokenExpiry()).thenReturn(300L);
        createSignedIdToken();
        createSignedAccessToken();
        Map<String, Object> additionalTokenClaims = new HashMap<>();
        additionalTokenClaims.put("nonce", nonce);
        Set<String> claimsForListOfScopes =
                ValidScopes.getClaimsForListOfScopes(SCOPES.toStringList());
        OIDCTokenResponse tokenResponse =
                tokenService.generateTokenResponse(
                        CLIENT_ID,
                        INTERNAL_SUBJECT,
                        SCOPES,
                        additionalTokenClaims,
                        PUBLIC_SUBJECT,
                        VOT,
                        Collections.singletonList(
                                new ClientConsent(
                                        CLIENT_ID,
                                        claimsForListOfScopes,
                                        LocalDateTime.now(ZoneId.of("UTC")).toString())),
                        false);

        assertEquals(
                BASE_URL, tokenResponse.getOIDCTokens().getIDToken().getJWTClaimsSet().getIssuer());
        assertEquals(
                PUBLIC_SUBJECT.getValue(),
                tokenResponse.getOIDCTokens().getIDToken().getJWTClaimsSet().getClaim("sub"));
        assertNull(tokenResponse.getOIDCTokens().getRefreshToken());
        String accessTokenKey = ACCESS_TOKEN_PREFIX + CLIENT_ID + "." + PUBLIC_SUBJECT;
        AccessTokenStore accessTokenStore =
                new AccessTokenStore(
                        tokenResponse.getOIDCTokens().getAccessToken().getValue(),
                        INTERNAL_SUBJECT.getValue());
        verify(redisConnectionService)
                .saveWithExpiry(
                        accessTokenKey,
                        new ObjectMapper().writeValueAsString(accessTokenStore),
                        300L);
        assertEquals(
                nonce.getValue(),
                tokenResponse.getOIDCTokens().getIDToken().getJWTClaimsSet().getClaim("nonce"));
    }

    @Test
    public void shouldSuccessfullyValidatePrivateKeyJWT() throws JOSEException {
        KeyPair keyPair = generateRsaKeyPair();
        String publicKey = Base64.getMimeEncoder().encodeToString(keyPair.getPublic().getEncoded());
        String requestParams = generateSerialisedPrivateKeyJWT(keyPair);
        assertThat(
                tokenService.validatePrivateKeyJWT(
                        requestParams, publicKey, "http://localhost/token"),
                equalTo(Optional.empty()));
    }

    @Test
    public void shouldReturnErrorIfUnableToValidatePrivateKeyJWT() throws JOSEException {
        KeyPair keyPair = generateRsaKeyPair();
        KeyPair keyPairTwo = generateRsaKeyPair();
        String publicKey =
                Base64.getMimeEncoder().encodeToString(keyPairTwo.getPublic().getEncoded());
        String requestParams = generateSerialisedPrivateKeyJWT(keyPair);
        assertThat(
                tokenService.validatePrivateKeyJWT(
                        requestParams, publicKey, "http://localhost/token"),
                equalTo(Optional.of(OAuth2Error.INVALID_CLIENT)));
    }

    @Test
    public void shouldSuccessfullyValidateTokenRequest() {
        Map<String, List<String>> customParams = new HashMap<>();
        customParams.put(
                "grant_type", Collections.singletonList(GrantType.AUTHORIZATION_CODE.getValue()));
        customParams.put("client_id", Collections.singletonList(CLIENT_ID));
        customParams.put("code", Collections.singletonList(AUTH_CODE));
        customParams.put("redirect_uri", Collections.singletonList(REDIRECT_URI));
        Optional<ErrorObject> errorObject =
                tokenService.validateTokenRequestParams(URLUtils.serializeParameters(customParams));

        assertThat(errorObject, equalTo(Optional.empty()));
    }

    @Test
    public void shouldReturnErrorIfClientIdIsMissingWhenValidatingTokenRequest() {
        Map<String, List<String>> customParams = new HashMap<>();
        customParams.put(
                "grant_type", Collections.singletonList(GrantType.AUTHORIZATION_CODE.getValue()));
        customParams.put("code", Collections.singletonList(AUTH_CODE));
        customParams.put("redirect_uri", Collections.singletonList(REDIRECT_URI));
        Optional<ErrorObject> errorObject =
                tokenService.validateTokenRequestParams(URLUtils.serializeParameters(customParams));

        assertThat(
                errorObject,
                equalTo(
                        Optional.of(
                                new ErrorObject(
                                        OAuth2Error.INVALID_REQUEST_CODE,
                                        "Request is missing client_id parameter"))));
    }

    @Test
    public void shouldReturnErrorIfRedirectUriIsMissingWhenValidatingTokenRequest() {
        Map<String, List<String>> customParams = new HashMap<>();
        customParams.put(
                "grant_type", Collections.singletonList(GrantType.AUTHORIZATION_CODE.getValue()));
        customParams.put("client_id", Collections.singletonList(CLIENT_ID));
        customParams.put("code", Collections.singletonList(AUTH_CODE));
        Optional<ErrorObject> errorObject =
                tokenService.validateTokenRequestParams(URLUtils.serializeParameters(customParams));

        assertThat(
                errorObject,
                equalTo(
                        Optional.of(
                                new ErrorObject(
                                        OAuth2Error.INVALID_REQUEST_CODE,
                                        "Request is missing redirect_uri parameter"))));
    }

    @Test
    public void shouldReturnErrorIfGrantTypeIsMissingWhenValidatingTokenRequest() {
        Map<String, List<String>> customParams = new HashMap<>();
        customParams.put("client_id", Collections.singletonList(CLIENT_ID));
        customParams.put("code", Collections.singletonList(AUTH_CODE));
        customParams.put("redirect_uri", Collections.singletonList(REDIRECT_URI));
        Optional<ErrorObject> errorObject =
                tokenService.validateTokenRequestParams(URLUtils.serializeParameters(customParams));

        assertThat(
                errorObject,
                equalTo(
                        Optional.of(
                                new ErrorObject(
                                        OAuth2Error.INVALID_REQUEST_CODE,
                                        "Request is missing grant_type parameter"))));
    }

    @Test
    public void shouldReturnErrorIfCodeIsMissingWhenValidatingTokenRequest() {
        Map<String, List<String>> customParams = new HashMap<>();
        customParams.put(
                "grant_type", Collections.singletonList(GrantType.AUTHORIZATION_CODE.getValue()));
        customParams.put("client_id", Collections.singletonList(CLIENT_ID));
        customParams.put("redirect_uri", Collections.singletonList(REDIRECT_URI));
        Optional<ErrorObject> errorObject =
                tokenService.validateTokenRequestParams(URLUtils.serializeParameters(customParams));

        assertThat(
                errorObject,
                equalTo(
                        Optional.of(
                                new ErrorObject(
                                        OAuth2Error.INVALID_REQUEST_CODE,
                                        "Request is missing code parameter"))));
    }

    @Test
    public void shouldReturnErrorIfGrantIsInvalidWhenValidatingTokenRequest() {
        Map<String, List<String>> customParams = new HashMap<>();
        customParams.put("grant_type", Collections.singletonList("client_credentials"));
        customParams.put("client_id", Collections.singletonList(CLIENT_ID));
        customParams.put("code", Collections.singletonList(AUTH_CODE));
        customParams.put("redirect_uri", Collections.singletonList(REDIRECT_URI));
        Optional<ErrorObject> errorObject =
                tokenService.validateTokenRequestParams(URLUtils.serializeParameters(customParams));

        assertThat(errorObject, equalTo(Optional.of(OAuth2Error.UNSUPPORTED_GRANT_TYPE)));
    }

    @Test
    public void shouldSuccessfullyValidateRefreshTokenRequest() {
        Scope scope = new Scope(OIDCScopeValue.OPENID, OIDCScopeValue.EMAIL);
        RefreshToken refreshToken = new RefreshToken();
        Map<String, List<String>> customParams = new HashMap<>();
        customParams.put(
                "grant_type", Collections.singletonList(GrantType.REFRESH_TOKEN.getValue()));
        customParams.put("client_id", Collections.singletonList(CLIENT_ID));
        customParams.put("scope", Collections.singletonList(scope.toString()));
        customParams.put("refresh_token", Collections.singletonList(refreshToken.getValue()));

        Optional<ErrorObject> errorObject =
                tokenService.validateTokenRequestParams(URLUtils.serializeParameters(customParams));
        assertTrue(errorObject.isEmpty());
    }

    @Test
    public void shouldReturnErrorWhenValidatingRefreshTokenRequestWithWrongGrant() {
        Scope scope = new Scope(OIDCScopeValue.OPENID, OIDCScopeValue.EMAIL);
        RefreshToken refreshToken = new RefreshToken();
        Map<String, List<String>> customParams = new HashMap<>();
        customParams.put(
                "grant_type", Collections.singletonList(GrantType.AUTHORIZATION_CODE.getValue()));
        customParams.put("client_id", Collections.singletonList(CLIENT_ID));
        customParams.put("scope", Collections.singletonList(scope.toString()));
        customParams.put("refresh_token", Collections.singletonList(refreshToken.getValue()));

        Optional<ErrorObject> errorObject =
                tokenService.validateTokenRequestParams(URLUtils.serializeParameters(customParams));

        assertTrue(errorObject.isPresent());
    }

    private String generateSerialisedPrivateKeyJWT(KeyPair keyPair) throws JOSEException {
        PrivateKeyJWT privateKeyJWT =
                new PrivateKeyJWT(
                        new ClientID("client-id"),
                        URI.create("http://localhost/token"),
                        JWSAlgorithm.RS256,
                        (RSAPrivateKey) keyPair.getPrivate(),
                        null,
                        null);
        Map<String, List<String>> privateKeyParams = privateKeyJWT.toParameters();
        privateKeyParams.putAll(privateKeyParams);
        return URLUtils.serializeParameters(privateKeyParams);
    }

    private void createSignedIdToken() throws JOSEException {
        ECKey ecSigningKey =
                new ECKeyGenerator(Curve.P_256)
                        .keyID(KEY_ID)
                        .algorithm(JWSAlgorithm.ES256)
                        .generate();
        ECDSASigner ecdsaSigner = new ECDSASigner(ecSigningKey);
        SignedJWT signedIdToken = createSignedIdToken(ecdsaSigner);
        SignResult idTokenSignedResult = new SignResult();
        byte[] idTokenSignatureDer =
                ECDSA.transcodeSignatureToDER(signedIdToken.getSignature().decode());
        idTokenSignedResult.setSignature(ByteBuffer.wrap(idTokenSignatureDer));
        idTokenSignedResult.setKeyId(KEY_ID);
        idTokenSignedResult.setSigningAlgorithm(JWSAlgorithm.ES256.getName());
        when(kmsConnectionService.sign(any(SignRequest.class))).thenReturn(idTokenSignedResult);
    }

    private SignedJWT createSignedIdToken(JWSSigner signer) {
        LocalDateTime localDateTime = LocalDateTime.now().plusMinutes(2);
        Date expiryDate = Date.from(localDateTime.atZone(ZoneId.of("UTC")).toInstant());
        return TokenGeneratorHelper.generateIDToken(
                CLIENT_ID, PUBLIC_SUBJECT, BASE_URL, signer, KEY_ID, expiryDate);
    }

    private void createSignedAccessToken() throws JOSEException {
        ECKey ecSigningKey =
                new ECKeyGenerator(Curve.P_256)
                        .keyID(KEY_ID)
                        .algorithm(JWSAlgorithm.ES256)
                        .generate();
        ECDSASigner signer = new ECDSASigner(ecSigningKey);
        SignedJWT signedJWT =
                TokenGeneratorHelper.generateSignedToken(
                        CLIENT_ID,
                        BASE_URL,
                        SCOPES.toStringList(),
                        signer,
                        PUBLIC_SUBJECT,
                        ecSigningKey.getKeyID());
        SignResult accessTokenResult = new SignResult();
        byte[] accessTokenSignatureDer =
                ECDSA.transcodeSignatureToDER(signedJWT.getSignature().decode());
        accessTokenResult.setSignature(ByteBuffer.wrap(accessTokenSignatureDer));
        accessTokenResult.setKeyId(KEY_ID);
        accessTokenResult.setSigningAlgorithm(JWSAlgorithm.ES256.getName());
        when(kmsConnectionService.sign(any(SignRequest.class))).thenReturn(accessTokenResult);
    }

    private KeyPair generateRsaKeyPair() {
        KeyPairGenerator kpg;
        try {
            kpg = KeyPairGenerator.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }
}
