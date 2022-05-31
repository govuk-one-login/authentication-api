package uk.gov.di.authentication.shared.services;

import com.amazonaws.services.kms.model.GetPublicKeyRequest;
import com.amazonaws.services.kms.model.GetPublicKeyResult;
import com.amazonaws.services.kms.model.SignRequest;
import com.amazonaws.services.kms.model.SignResult;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
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
import com.nimbusds.oauth2.sdk.auth.JWTAuthenticationClaimsSet;
import com.nimbusds.oauth2.sdk.auth.PrivateKeyJWT;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.oauth2.sdk.util.JSONArrayUtils;
import com.nimbusds.oauth2.sdk.util.URLUtils;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCClaimsRequest;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.claims.AccessTokenHash;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSetRequest;
import net.minidev.json.JSONArray;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.mockito.ArgumentCaptor;
import uk.gov.di.authentication.shared.entity.AccessTokenStore;
import uk.gov.di.authentication.shared.entity.ClientConsent;
import uk.gov.di.authentication.shared.entity.CredentialTrustLevel;
import uk.gov.di.authentication.shared.entity.RefreshTokenStore;
import uk.gov.di.authentication.shared.entity.ValidScopes;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.sharedtest.helper.TokenGeneratorHelper;
import uk.gov.di.authentication.sharedtest.logging.CaptureLoggingExtension;

import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.text.ParseException;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.temporal.ChronoUnit;
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
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.startsWith;
import static org.hamcrest.core.Is.is;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.shared.helpers.ConstructUriHelper.buildURI;
import static uk.gov.di.authentication.sharedtest.logging.LogEventMatcher.withMessageContaining;

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
    private Nonce nonce;
    private static final String CLIENT_ID = "client-id";
    private static final String AUTH_CODE = new AuthorizationCode().toString();
    private static final String REDIRECT_URI = "http://localhost/redirect";
    private static final String TOKEN_URI = "http://localhost/token";
    private static final String BASE_URL = "https://example.com";
    private static final String KEY_ID = "14342354354353";
    private static final String REFRESH_TOKEN_PREFIX = "REFRESH_TOKEN:";
    private static final String ACCESS_TOKEN_PREFIX = "ACCESS_TOKEN:";

    private static final Json objectMapper = SerializationService.getInstance();

    @RegisterExtension
    public final CaptureLoggingExtension logging = new CaptureLoggingExtension(TokenService.class);

    @BeforeEach
    void setUp() {
        Optional<String> baseUrl = Optional.of(BASE_URL);
        when(configurationService.getOidcApiBaseURL()).thenReturn(baseUrl);
        when(configurationService.getAccessTokenExpiry()).thenReturn(300L);
        when(configurationService.getIDTokenExpiry()).thenReturn(120L);
        when(configurationService.getSessionExpiry()).thenReturn(300L);
        when(kmsConnectionService.getPublicKey(any(GetPublicKeyRequest.class)))
                .thenReturn(new GetPublicKeyResult().withKeyId("789789789789789"));

        nonce = new Nonce();
    }

    @AfterEach
    void tearDown() {
        assertThat(logging.events(), not(hasItem(withMessageContaining(CLIENT_ID))));
    }

    @Test
    void shouldGenerateTokenResponseWithRefreshToken()
            throws ParseException, JOSEException, Json.JsonException {
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
                        false,
                        null,
                        false);

        assertSuccessfullTokenResponse(tokenResponse);
        assertNotNull(tokenResponse.getOIDCTokens().getRefreshToken());
        RefreshTokenStore refreshTokenStore =
                new RefreshTokenStore(
                        tokenResponse.getOIDCTokens().getRefreshToken().getValue(),
                        INTERNAL_SUBJECT.getValue());
        ArgumentCaptor<String> redisKey = ArgumentCaptor.forClass(String.class);
        verify(redisConnectionService)
                .saveWithExpiry(
                        redisKey.capture(),
                        eq(objectMapper.writeValueAsString(refreshTokenStore)),
                        eq(300L));

        var refreshToken =
                SignedJWT.parse(tokenResponse.getOIDCTokens().getRefreshToken().getValue());
        var jti = refreshToken.getJWTClaimsSet().getJWTID();
        assertThat(redisKey.getValue(), startsWith(REFRESH_TOKEN_PREFIX));
        assertThat(redisKey.getValue().split(":")[1], equalTo(jti));
    }

    @Test
    void shouldOnlyIncludeIdentityClaimsInAccessTokenWhenRequested()
            throws ParseException, JOSEException, Json.JsonException,
                    com.nimbusds.oauth2.sdk.ParseException {
        var claimsSetRequest = new ClaimsSetRequest().add("nickname").add("birthdate");
        var oidcClaimsRequest = new OIDCClaimsRequest().withUserInfoClaimsRequest(claimsSetRequest);

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
                        false,
                        oidcClaimsRequest,
                        false);

        assertSuccessfullTokenResponse(tokenResponse);

        assertNotNull(tokenResponse.getOIDCTokens().getRefreshToken());
        assertNull(
                SignedJWT.parse(tokenResponse.getOIDCTokens().getRefreshToken().getValue())
                        .getJWTClaimsSet()
                        .getClaim("claims"));
        JSONArray jsonarray =
                JSONArrayUtils.parse(
                        SignedJWT.parse(tokenResponse.getOIDCTokens().getAccessToken().getValue())
                                .getJWTClaimsSet()
                                .getClaim("claims")
                                .toString());

        assertTrue(jsonarray.contains("nickname"));
        assertTrue(jsonarray.contains("birthdate"));

        RefreshTokenStore refreshTokenStore =
                new RefreshTokenStore(
                        tokenResponse.getOIDCTokens().getRefreshToken().getValue(),
                        INTERNAL_SUBJECT.getValue());

        ArgumentCaptor<String> redisKey = ArgumentCaptor.forClass(String.class);
        verify(redisConnectionService)
                .saveWithExpiry(
                        redisKey.capture(),
                        eq(objectMapper.writeValueAsString(refreshTokenStore)),
                        eq(300L));

        var refreshToken =
                SignedJWT.parse(tokenResponse.getOIDCTokens().getRefreshToken().getValue());
        var jti = refreshToken.getJWTClaimsSet().getJWTID();
        assertThat(redisKey.getValue(), startsWith(REFRESH_TOKEN_PREFIX));
        assertThat(redisKey.getValue().split(":")[1], equalTo(jti));
    }

    @Test
    void shouldGenerateTokenResponseWithoutRefreshTokenWhenOfflineAccessScopeIsMissing()
            throws ParseException, JOSEException, Json.JsonException {
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
                        false,
                        null,
                        false);

        assertSuccessfullTokenResponse(tokenResponse);

        assertNull(tokenResponse.getOIDCTokens().getRefreshToken());
    }

    @Test
    void shouldSuccessfullyValidatePrivateKeyJWT() throws JOSEException {
        KeyPair keyPair = generateRsaKeyPair();
        String publicKey = Base64.getMimeEncoder().encodeToString(keyPair.getPublic().getEncoded());
        Date expiryDate = NowHelper.nowPlus(5, ChronoUnit.MINUTES);
        String requestParams = generateSerialisedPrivateKeyJWT(keyPair, expiryDate.getTime());
        assertThat(
                tokenService.validatePrivateKeyJWT(requestParams, publicKey, TOKEN_URI, CLIENT_ID),
                equalTo(Optional.empty()));
    }

    @Test
    void shouldFailToValidatePrivateKeyJWTIfExpired() throws JOSEException {
        KeyPair keyPair = generateRsaKeyPair();
        String publicKey = Base64.getMimeEncoder().encodeToString(keyPair.getPublic().getEncoded());
        Date expiryDate = NowHelper.nowMinus(2, ChronoUnit.MINUTES);
        String requestParams = generateSerialisedPrivateKeyJWT(keyPair, expiryDate.getTime());
        assertThat(
                tokenService.validatePrivateKeyJWT(requestParams, publicKey, TOKEN_URI, CLIENT_ID),
                equalTo(Optional.of(OAuth2Error.INVALID_GRANT)));
    }

    @Test
    void shouldFailToValidatePrivateKeyJWTIfInvalidClientId() throws JOSEException {
        KeyPair keyPair = generateRsaKeyPair();
        String publicKey = Base64.getMimeEncoder().encodeToString(keyPair.getPublic().getEncoded());
        Date expiryDate = NowHelper.nowPlus(5, ChronoUnit.MINUTES);
        String requestParams = generateSerialisedPrivateKeyJWT(keyPair, expiryDate.getTime());
        assertThat(
                tokenService.validatePrivateKeyJWT(
                        requestParams, publicKey, TOKEN_URI, "wrong-client-id"),
                equalTo(Optional.of(OAuth2Error.INVALID_CLIENT)));
    }

    @Test
    void shouldReturnErrorIfUnableToValidatePrivateKeyJWTSignature() throws JOSEException {
        KeyPair keyPair = generateRsaKeyPair();
        KeyPair keyPairTwo = generateRsaKeyPair();
        String publicKey =
                Base64.getMimeEncoder().encodeToString(keyPairTwo.getPublic().getEncoded());
        Date expiryDate = NowHelper.nowPlus(5, ChronoUnit.MINUTES);
        String requestParams = generateSerialisedPrivateKeyJWT(keyPair, expiryDate.getTime());
        assertThat(
                tokenService.validatePrivateKeyJWT(requestParams, publicKey, TOKEN_URI, CLIENT_ID),
                equalTo(Optional.of(OAuth2Error.INVALID_CLIENT)));
    }

    @Test
    void shouldSuccessfullyGetClientFromPrivateKeyJWT() throws JOSEException {
        KeyPair keyPair = generateRsaKeyPair();
        Date expiryDate = NowHelper.nowPlus(5, ChronoUnit.MINUTES);
        String requestParams =
                generateSerialisedPrivateKeyJWT(keyPair, expiryDate.getTime(), CLIENT_ID);
        assertThat(
                tokenService.getClientIDFromPrivateKeyJWT(requestParams),
                equalTo(Optional.of(CLIENT_ID)));
    }

    @Test
    void shouldSuccessfullyValidateTokenRequest() {
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
    void shouldReturnErrorIfRedirectUriIsMissingWhenValidatingTokenRequest() {
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
    void shouldReturnErrorIfGrantTypeIsMissingWhenValidatingTokenRequest() {
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
    void shouldReturnErrorIfCodeIsMissingWhenValidatingTokenRequest() {
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
    void shouldReturnErrorIfGrantIsInvalidWhenValidatingTokenRequest() {
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
    void shouldSuccessfullyValidateRefreshTokenRequest() {
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
    void shouldReturnErrorWhenValidatingRefreshTokenRequestWithWrongGrant() {
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

    private String generateSerialisedPrivateKeyJWT(KeyPair keyPair, long expiryTime)
            throws JOSEException {
        return generateSerialisedPrivateKeyJWT(keyPair, expiryTime, CLIENT_ID);
    }

    private String generateSerialisedPrivateKeyJWT(
            KeyPair keyPair, long expiryTime, String clientId) throws JOSEException {

        JWTAuthenticationClaimsSet claimsSet =
                new JWTAuthenticationClaimsSet(new ClientID(clientId), new Audience(TOKEN_URI));
        claimsSet.getExpirationTime().setTime(expiryTime);
        PrivateKeyJWT privateKeyJWT =
                new PrivateKeyJWT(
                        claimsSet,
                        JWSAlgorithm.RS256,
                        (RSAPrivateKey) keyPair.getPrivate(),
                        null,
                        null);
        Map<String, List<String>> privateKeyParams = privateKeyJWT.toParameters();
        return URLUtils.serializeParameters(privateKeyParams);
    }

    private void createSignedIdToken() throws JOSEException {
        ECKey ecSigningKey =
                new ECKeyGenerator(Curve.P_256)
                        .keyID(KEY_ID)
                        .algorithm(JWSAlgorithm.ES256)
                        .generate();
        ECDSASigner ecdsaSigner = new ECDSASigner(ecSigningKey);
        SignedJWT signedIdToken = createSignedIdToken(ecSigningKey);
        SignResult idTokenSignedResult = new SignResult();
        byte[] idTokenSignatureDer =
                ECDSA.transcodeSignatureToDER(signedIdToken.getSignature().decode());
        idTokenSignedResult.setSignature(ByteBuffer.wrap(idTokenSignatureDer));
        idTokenSignedResult.setKeyId(KEY_ID);
        idTokenSignedResult.setSigningAlgorithm(JWSAlgorithm.ES256.getName());
        when(kmsConnectionService.sign(any(SignRequest.class))).thenReturn(idTokenSignedResult);
    }

    private SignedJWT createSignedIdToken(ECKey ecSigningKey) {
        Date expiryDate = NowHelper.nowPlus(2, ChronoUnit.MINUTES);
        return TokenGeneratorHelper.generateIDToken(
                CLIENT_ID, PUBLIC_SUBJECT, BASE_URL, ecSigningKey, expiryDate);
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

    private void assertSuccessfullTokenResponse(OIDCTokenResponse tokenResponse)
            throws ParseException, Json.JsonException {
        String accessTokenKey = ACCESS_TOKEN_PREFIX + CLIENT_ID + "." + PUBLIC_SUBJECT;
        assertNotNull(tokenResponse.getOIDCTokens().getAccessToken());
        AccessTokenStore accessTokenStore =
                new AccessTokenStore(
                        tokenResponse.getOIDCTokens().getAccessToken().getValue(),
                        INTERNAL_SUBJECT.getValue());
        verify(redisConnectionService)
                .saveWithExpiry(
                        accessTokenKey, objectMapper.writeValueAsString(accessTokenStore), 300L);

        var header = (JWSHeader) tokenResponse.getOIDCTokens().getIDToken().getHeader();

        assertThat(
                header.getKeyID(),
                is("1d504aece298a14d74ee0a02b6740b4372a1fab4206778e486ba72770ff4beb8"));

        assertThat(
                tokenResponse.getOIDCTokens().getIDToken().getJWTClaimsSet().getClaims().size(),
                equalTo(9));
        assertThat(
                tokenResponse.getOIDCTokens().getIDToken().getJWTClaimsSet().getClaim("sub"),
                equalTo(PUBLIC_SUBJECT.getValue()));
        assertThat(
                tokenResponse.getOIDCTokens().getIDToken().getJWTClaimsSet().getClaim("nonce"),
                equalTo(nonce.getValue()));
        assertThat(
                tokenResponse.getOIDCTokens().getIDToken().getJWTClaimsSet().getClaim("vtm"),
                equalTo(buildURI(BASE_URL, "/trustmark").toString()));
        assertThat(
                tokenResponse.getOIDCTokens().getIDToken().getJWTClaimsSet().getIssuer(),
                equalTo(BASE_URL));
        assertThat(
                tokenResponse.getOIDCTokens().getIDToken().getJWTClaimsSet().getClaim("at_hash"),
                equalTo(
                        AccessTokenHash.compute(
                                        tokenResponse.getOIDCTokens().getAccessToken(),
                                        JWSAlgorithm.ES256,
                                        null)
                                .toString()));
    }
}
