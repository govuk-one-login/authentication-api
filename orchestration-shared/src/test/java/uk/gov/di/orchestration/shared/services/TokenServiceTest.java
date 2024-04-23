package uk.gov.di.orchestration.shared.services;

import com.google.gson.Gson;
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
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.AccessToken;
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
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.model.GetPublicKeyRequest;
import software.amazon.awssdk.services.kms.model.GetPublicKeyResponse;
import software.amazon.awssdk.services.kms.model.SignRequest;
import software.amazon.awssdk.services.kms.model.SignResponse;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;
import uk.gov.di.orchestration.shared.entity.AccessTokenStore;
import uk.gov.di.orchestration.shared.entity.ClientConsent;
import uk.gov.di.orchestration.shared.entity.RefreshTokenStore;
import uk.gov.di.orchestration.shared.entity.ValidScopes;
import uk.gov.di.orchestration.shared.entity.vectoroftrust.CredentialTrustLevelCode;
import uk.gov.di.orchestration.shared.helpers.NowHelper;
import uk.gov.di.orchestration.shared.serialization.Json;
import uk.gov.di.orchestration.sharedtest.helper.SubjectHelper;
import uk.gov.di.orchestration.sharedtest.helper.TokenGeneratorHelper;
import uk.gov.di.orchestration.sharedtest.logging.CaptureLoggingExtension;

import java.net.URI;
import java.text.ParseException;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.temporal.ChronoUnit;
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
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.orchestration.shared.helpers.ConstructUriHelper.buildURI;
import static uk.gov.di.orchestration.sharedtest.logging.LogEventMatcher.withMessageContaining;

class TokenServiceTest {

    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final KmsConnectionService kmsConnectionService = mock(KmsConnectionService.class);
    private final RedisConnectionService redisConnectionService =
            mock(RedisConnectionService.class);
    private final TokenService tokenService =
            new TokenService(configurationService, redisConnectionService, kmsConnectionService);
    private static final Subject PUBLIC_SUBJECT = SubjectHelper.govUkSignInSubject();
    private static final Subject INTERNAL_SUBJECT = SubjectHelper.govUkSignInSubject();
    private static final Subject INTERNAL_PAIRWISE_SUBJECT = SubjectHelper.govUkSignInSubject();
    private static final Scope SCOPES =
            new Scope(OIDCScopeValue.OPENID, OIDCScopeValue.EMAIL, OIDCScopeValue.PHONE);
    private static final CredentialTrustLevelCode VOT = CredentialTrustLevelCode.C2;
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
    private static final String BASE_URL = "https://example.com";
    private static final String KEY_ID = "14342354354353";
    private static final String REFRESH_TOKEN_PREFIX = "REFRESH_TOKEN:";
    private static final String ACCESS_TOKEN_PREFIX = "ACCESS_TOKEN:";
    private static final String STORAGE_TOKEN_PREFIX =
            "eyJraWQiOiIxZDUwNGFlY2UyOThhMTRkNzRlZTBhMDJiNjc0MGI0MzcyYTFmYWI0MjA2Nzc4ZTQ4NmJhNzI3NzBmZjRiZWI4IiwiYWxnIjoiRVMyNTYifQ.";
    private static final String CREDENTIAL_STORE_URI = "https://credential-store.account.gov.uk";
    private static final String IPV_AUDIENCE = "https://identity.test.account.gov.uk";

    private static final Json objectMapper = SerializationService.getInstance();

    @RegisterExtension
    public final CaptureLoggingExtension logging = new CaptureLoggingExtension(TokenService.class);

    @BeforeEach
    void setUp() {
        when(configurationService.getOidcApiBaseURL()).thenReturn(Optional.of(BASE_URL));
        when(configurationService.getAccessTokenExpiry()).thenReturn(300L);
        when(configurationService.getIDTokenExpiry()).thenReturn(120L);
        when(configurationService.getSessionExpiry()).thenReturn(300L);
        when(configurationService.getEnvironment()).thenReturn("test");
        when(kmsConnectionService.getPublicKey(any(GetPublicKeyRequest.class)))
                .thenReturn(GetPublicKeyResponse.builder().keyId("789789789789789").build());

        nonce = new Nonce();
    }

    @AfterEach
    void tearDown() {
        assertThat(logging.events(), not(hasItem(withMessageContaining(CLIENT_ID))));
    }

    @Test
    void shouldGenerateTokenResponseWithRefreshToken()
            throws ParseException, JOSEException, Json.JsonException {
        when(configurationService.getExternalTokenSigningKeyAlias()).thenReturn(KEY_ID);
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
                        INTERNAL_PAIRWISE_SUBJECT,
                        Collections.singletonList(
                                new ClientConsent(
                                        CLIENT_ID,
                                        claimsForListOfScopes,
                                        LocalDateTime.now(ZoneId.of("UTC")).toString())),
                        false,
                        null,
                        false,
                        JWSAlgorithm.ES256,
                        "client-session-id",
                        VOT);

        assertSuccessfulTokenResponse(tokenResponse);

        assertNotNull(tokenResponse.getOIDCTokens().getRefreshToken());
        RefreshTokenStore refreshTokenStore =
                new RefreshTokenStore(
                        tokenResponse.getOIDCTokens().getRefreshToken().getValue(),
                        INTERNAL_SUBJECT.getValue(),
                        INTERNAL_PAIRWISE_SUBJECT.getValue());
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
    void shouldGenerateWellFormedStorageToken() throws JOSEException {
        when(configurationService.getCredentialStoreURI())
                .thenReturn(URI.create(CREDENTIAL_STORE_URI));
        when(configurationService.getIPVAudience()).thenReturn(IPV_AUDIENCE);
        createSignedStorageToken();

        AccessToken token = tokenService.generateStorageToken(new Subject());
        String[] splitToken = token.toString().split("\\.");

        verify(configurationService).getStorageTokenSigningKeyAlias();
        assertEquals(3, splitToken.length);
        assertThat(token.toString(), startsWith(STORAGE_TOKEN_PREFIX));
    }

    @Test
    void shouldOnlyIncludeIdentityClaimsInAccessTokenWhenRequested()
            throws ParseException,
                    JOSEException,
                    Json.JsonException,
                    com.nimbusds.oauth2.sdk.ParseException {
        var claimsSetRequest = new ClaimsSetRequest().add("nickname").add("birthdate");
        var oidcClaimsRequest = new OIDCClaimsRequest().withUserInfoClaimsRequest(claimsSetRequest);

        when(configurationService.getExternalTokenSigningKeyAlias()).thenReturn(KEY_ID);
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
                        INTERNAL_PAIRWISE_SUBJECT,
                        Collections.singletonList(
                                new ClientConsent(
                                        CLIENT_ID,
                                        claimsForListOfScopes,
                                        LocalDateTime.now(ZoneId.of("UTC")).toString())),
                        false,
                        oidcClaimsRequest,
                        false,
                        JWSAlgorithm.ES256,
                        "client-session-id",
                        VOT);

        assertSuccessfulTokenResponse(tokenResponse);

        assertNotNull(tokenResponse.getOIDCTokens().getRefreshToken());
        assertNull(
                SignedJWT.parse(tokenResponse.getOIDCTokens().getRefreshToken().getValue())
                        .getJWTClaimsSet()
                        .getClaim("claims"));
        JSONArray jsonarray =
                JSONArrayUtils.parse(
                        new Gson()
                                .toJson(
                                        SignedJWT.parse(
                                                        tokenResponse
                                                                .getOIDCTokens()
                                                                .getAccessToken()
                                                                .getValue())
                                                .getJWTClaimsSet()
                                                .getClaim("claims")));

        assertTrue(jsonarray.contains("nickname"));
        assertTrue(jsonarray.contains("birthdate"));

        RefreshTokenStore refreshTokenStore =
                new RefreshTokenStore(
                        tokenResponse.getOIDCTokens().getRefreshToken().getValue(),
                        INTERNAL_SUBJECT.getValue(),
                        INTERNAL_PAIRWISE_SUBJECT.getValue());

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
        when(configurationService.getExternalTokenSigningKeyAlias()).thenReturn(KEY_ID);
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
                        INTERNAL_PAIRWISE_SUBJECT,
                        Collections.singletonList(
                                new ClientConsent(
                                        CLIENT_ID,
                                        claimsForListOfScopes,
                                        LocalDateTime.now(ZoneId.of("UTC")).toString())),
                        false,
                        null,
                        false,
                        JWSAlgorithm.ES256,
                        "client-session-id",
                        VOT);

        assertSuccessfulTokenResponse(tokenResponse);

        assertNull(tokenResponse.getOIDCTokens().getRefreshToken());
    }

    @Test
    void shouldNotIncludeInternalIdentifiersInTokens() throws ParseException, JOSEException {
        when(configurationService.getExternalTokenSigningKeyAlias()).thenReturn(KEY_ID);
        when(configurationService.getAccessTokenExpiry()).thenReturn(300L);
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
                        INTERNAL_PAIRWISE_SUBJECT,
                        Collections.singletonList(
                                new ClientConsent(
                                        CLIENT_ID,
                                        claimsForListOfScopes,
                                        LocalDateTime.now(ZoneId.of("UTC")).toString())),
                        false,
                        null,
                        false,
                        JWSAlgorithm.ES256,
                        "client-session-id",
                        VOT);

        var parsedAccessToken =
                SignedJWT.parse(tokenResponse.getOIDCTokens().getAccessToken().getValue())
                        .getPayload()
                        .toString();
        assertFalse(parsedAccessToken.contains(INTERNAL_SUBJECT.getValue()));
        assertFalse(parsedAccessToken.contains(INTERNAL_PAIRWISE_SUBJECT.getValue()));
        var parsedRefreshToken =
                SignedJWT.parse(tokenResponse.getOIDCTokens().getRefreshToken().getValue())
                        .getPayload()
                        .toString();
        assertFalse(parsedRefreshToken.contains(INTERNAL_SUBJECT.getValue()));
        assertFalse(parsedRefreshToken.contains(INTERNAL_PAIRWISE_SUBJECT.getValue()));
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

    private void createSignedIdToken() throws JOSEException {
        ECKey ecSigningKey =
                new ECKeyGenerator(Curve.P_256)
                        .keyID(KEY_ID)
                        .algorithm(JWSAlgorithm.ES256)
                        .generate();
        SignedJWT signedIdToken = createSignedIdToken(ecSigningKey);
        byte[] idTokenSignatureDer =
                ECDSA.transcodeSignatureToDER(signedIdToken.getSignature().decode());
        SignResponse idTokenSignedResult =
                SignResponse.builder()
                        .signature(SdkBytes.fromByteArray(idTokenSignatureDer))
                        .keyId(KEY_ID)
                        .signingAlgorithm(SigningAlgorithmSpec.ECDSA_SHA_256)
                        .build();

        when(kmsConnectionService.sign(any(SignRequest.class))).thenReturn(idTokenSignedResult);
    }

    private void createSignedStorageToken() throws JOSEException {
        ECKey ecSigningKey =
                new ECKeyGenerator(Curve.P_256)
                        .keyID(KEY_ID)
                        .algorithm(JWSAlgorithm.ES256)
                        .generate();
        SignedJWT signedIdToken = createSignedIdToken(ecSigningKey);
        byte[] idTokenSignatureDer =
                ECDSA.transcodeSignatureToDER(signedIdToken.getSignature().decode());
        SignResponse idTokenSignedResult =
                SignResponse.builder()
                        .signature(SdkBytes.fromByteArray(idTokenSignatureDer))
                        .keyId(KEY_ID)
                        .signingAlgorithm(SigningAlgorithmSpec.ECDSA_SHA_256)
                        .build();

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
        byte[] accessTokenSignatureDer =
                ECDSA.transcodeSignatureToDER(signedJWT.getSignature().decode());
        SignResponse accessTokenResult =
                SignResponse.builder()
                        .signature(SdkBytes.fromByteArray(accessTokenSignatureDer))
                        .signingAlgorithm(SigningAlgorithmSpec.ECDSA_SHA_256)
                        .keyId(KEY_ID)
                        .build();

        when(kmsConnectionService.sign(any(SignRequest.class))).thenReturn(accessTokenResult);
    }

    private void assertSuccessfulTokenResponse(OIDCTokenResponse tokenResponse)
            throws ParseException, Json.JsonException {
        String accessTokenKey = ACCESS_TOKEN_PREFIX + CLIENT_ID + "." + PUBLIC_SUBJECT;
        assertNotNull(tokenResponse.getOIDCTokens().getAccessToken());
        AccessTokenStore accessTokenStore =
                new AccessTokenStore(
                        tokenResponse.getOIDCTokens().getAccessToken().getValue(),
                        INTERNAL_SUBJECT.getValue(),
                        INTERNAL_PAIRWISE_SUBJECT.getValue());
        verify(redisConnectionService)
                .saveWithExpiry(
                        accessTokenKey, objectMapper.writeValueAsString(accessTokenStore), 300L);

        var header = (JWSHeader) tokenResponse.getOIDCTokens().getIDToken().getHeader();

        assertThat(tokenResponse.getOIDCTokens().getAccessToken().getLifetime(), is(300L));

        assertThat(
                header.getKeyID(),
                is("1d504aece298a14d74ee0a02b6740b4372a1fab4206778e486ba72770ff4beb8"));

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

        assertThat(
                tokenResponse.getOIDCTokens().getIDToken().getJWTClaimsSet().getStringClaim("sid"),
                is("client-session-id"));
    }
}
