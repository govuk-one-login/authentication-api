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
import com.nimbusds.jwt.JWTClaimsSet;
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
import org.approvaltests.JsonApprovals;
import org.approvaltests.core.Options;
import org.approvaltests.scrubbers.GuidScrubber;
import org.approvaltests.scrubbers.RegExScrubber;
import org.approvaltests.scrubbers.Scrubbers;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.model.GetPublicKeyRequest;
import software.amazon.awssdk.services.kms.model.GetPublicKeyResponse;
import software.amazon.awssdk.services.kms.model.SignRequest;
import software.amazon.awssdk.services.kms.model.SignResponse;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;
import uk.gov.di.orchestration.shared.api.OidcAPI;
import uk.gov.di.orchestration.shared.entity.CredentialTrustLevel;
import uk.gov.di.orchestration.shared.helpers.NowHelper;
import uk.gov.di.orchestration.sharedtest.helper.SubjectHelper;
import uk.gov.di.orchestration.sharedtest.helper.TokenGeneratorHelper;
import uk.gov.di.orchestration.sharedtest.logging.CaptureLoggingExtension;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.samePropertyValuesAs;
import static org.hamcrest.Matchers.startsWith;
import static org.hamcrest.core.Is.is;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.orchestration.shared.helpers.ConstructUriHelper.buildURI;
import static uk.gov.di.orchestration.shared.helpers.HashHelper.hashSha256String;
import static uk.gov.di.orchestration.sharedtest.logging.LogEventMatcher.withMessageContaining;

class TokenServiceTest {

    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final KmsConnectionService kmsConnectionService = mock(KmsConnectionService.class);
    private final OrchAccessTokenService orchAccessTokenService =
            mock(OrchAccessTokenService.class);
    private final OrchRefreshTokenService orchRefreshTokenService =
            mock(OrchRefreshTokenService.class);
    private final OidcAPI oidcApi = mock(OidcAPI.class);
    private final TokenService tokenService =
            new TokenService(
                    configurationService,
                    kmsConnectionService,
                    orchAccessTokenService,
                    orchRefreshTokenService,
                    oidcApi);
    private static final Subject PUBLIC_SUBJECT = SubjectHelper.govUkSignInSubject();
    private static final Subject INTERNAL_SUBJECT = SubjectHelper.govUkSignInSubject();
    private static final Subject INTERNAL_PAIRWISE_SUBJECT = SubjectHelper.govUkSignInSubject();
    private static final Subject FIXED_INTERNAL_PAIRWISE_SUBJECT =
            new Subject("urn:fdc:gov.uk:2022:TJLt3WaiGkLh8UqeisH2zVKGAP0");
    private static final String JOURNEY_ID = "client-session-id";
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
    private static final String OIDC_BASE_URI = "https://oidc.test.account.gov.uk";
    private static final String OIDC_TRUSTMARK_URI = "https://oidc.test.account.gov.uk/trustmark";
    private static final String KEY_ID = "14342354354353";
    private static final String STORAGE_TOKEN_PREFIX =
            "eyJraWQiOiIxZDUwNGFlY2UyOThhMTRkNzRlZTBhMDJiNjc0MGI0MzcyYTFmYWI0MjA2Nzc4ZTQ4NmJhNzI3NzBmZjRiZWI4IiwiYWxnIjoiRVMyNTYifQ.";
    private static final String CREDENTIAL_STORE_URI = "https://credential-store.account.gov.uk";
    private static final String IPV_AUDIENCE = "https://identity.test.account.gov.uk";
    private static final Long AUTH_TIME = NowHelper.now().toInstant().getEpochSecond() - 120L;

    @RegisterExtension
    public final CaptureLoggingExtension logging = new CaptureLoggingExtension(TokenService.class);

    @BeforeEach
    void setUp() {
        when(oidcApi.baseURI()).thenReturn(URI.create(OIDC_BASE_URI));
        when(oidcApi.trustmarkURI()).thenReturn(URI.create(OIDC_TRUSTMARK_URI));
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
    void shouldGenerateTokenResponseWithRefreshToken() throws ParseException, JOSEException {
        when(configurationService.getExternalTokenSigningKeyAlias()).thenReturn(KEY_ID);
        createSignedIdToken();
        createSignedAccessToken();
        Map<String, Object> additionalTokenClaims = new HashMap<>();
        additionalTokenClaims.put("nonce", nonce);

        OIDCTokenResponse tokenResponse =
                tokenService.generateTokenResponse(
                        CLIENT_ID,
                        SCOPES_OFFLINE_ACCESS,
                        additionalTokenClaims,
                        PUBLIC_SUBJECT,
                        INTERNAL_PAIRWISE_SUBJECT,
                        null,
                        false,
                        JWSAlgorithm.ES256,
                        JOURNEY_ID,
                        VOT,
                        AUTH_TIME,
                        AUTH_CODE);

        assertSuccessfulTokenResponse(tokenResponse);

        assertNotNull(tokenResponse.getOIDCTokens().getRefreshToken());
        String refreshTokenValue = tokenResponse.getOIDCTokens().getRefreshToken().getValue();
        var refreshToken = SignedJWT.parse(refreshTokenValue);
        var jti = refreshToken.getJWTClaimsSet().getJWTID();

        verify(orchRefreshTokenService)
                .saveRefreshToken(
                        jti,
                        INTERNAL_PAIRWISE_SUBJECT.getValue(),
                        refreshTokenValue,
                        AUTH_CODE,
                        JOURNEY_ID);
    }

    @Test
    void shouldGenerateWellFormedStorageToken() throws JOSEException, ParseException {
        when(configurationService.getCredentialStoreURI())
                .thenReturn(URI.create(CREDENTIAL_STORE_URI));
        when(configurationService.getIPVAudience()).thenReturn(IPV_AUDIENCE);
        createSignedStorageToken();

        AccessToken token = tokenService.generateStorageToken(FIXED_INTERNAL_PAIRWISE_SUBJECT);
        var parsedToken = SignedJWT.parse(token.getValue());

        verify(configurationService).getStorageTokenSigningKeyAlias();
        assertEquals(3, parsedToken.getParsedParts().length);
        assertThat(token.toString(), startsWith(STORAGE_TOKEN_PREFIX));
        var unixTimestampScrubber = new RegExScrubber("\\d{10}", "1700000000");
        var guidScrubber = new GuidScrubber();
        JsonApprovals.verifyAsJson(
                parsedToken.getJWTClaimsSet().toJSONObject(),
                new Options(Scrubbers.scrubAll(unixTimestampScrubber, guidScrubber)));
    }

    @Test
    void shouldOnlyIncludeIdentityClaimsInAccessTokenWhenRequested()
            throws ParseException, JOSEException, com.nimbusds.oauth2.sdk.ParseException {
        var claimsSetRequest = new ClaimsSetRequest().add("nickname").add("birthdate");
        var oidcClaimsRequest = new OIDCClaimsRequest().withUserInfoClaimsRequest(claimsSetRequest);

        when(configurationService.getExternalTokenSigningKeyAlias()).thenReturn(KEY_ID);
        createSignedIdToken();
        createSignedAccessToken();
        Map<String, Object> additionalTokenClaims = new HashMap<>();
        additionalTokenClaims.put("nonce", nonce);

        OIDCTokenResponse tokenResponse =
                tokenService.generateTokenResponse(
                        CLIENT_ID,
                        SCOPES_OFFLINE_ACCESS,
                        additionalTokenClaims,
                        PUBLIC_SUBJECT,
                        INTERNAL_PAIRWISE_SUBJECT,
                        oidcClaimsRequest,
                        false,
                        JWSAlgorithm.ES256,
                        JOURNEY_ID,
                        VOT,
                        AUTH_TIME,
                        AUTH_CODE);

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

        String refreshTokenValue = tokenResponse.getOIDCTokens().getRefreshToken().getValue();
        var refreshToken = SignedJWT.parse(refreshTokenValue);
        var jti = refreshToken.getJWTClaimsSet().getJWTID();

        verify(orchRefreshTokenService)
                .saveRefreshToken(
                        jti,
                        INTERNAL_PAIRWISE_SUBJECT.getValue(),
                        refreshTokenValue,
                        AUTH_CODE,
                        JOURNEY_ID);
    }

    @Test
    void shouldGenerateTokenResponseWithoutRefreshTokenWhenOfflineAccessScopeIsMissing()
            throws ParseException, JOSEException {
        when(configurationService.getExternalTokenSigningKeyAlias()).thenReturn(KEY_ID);
        when(configurationService.getAccessTokenExpiry()).thenReturn(300L);
        createSignedIdToken();
        createSignedAccessToken();
        Map<String, Object> additionalTokenClaims = new HashMap<>();
        additionalTokenClaims.put("nonce", nonce);
        OIDCTokenResponse tokenResponse =
                tokenService.generateTokenResponse(
                        CLIENT_ID,
                        SCOPES,
                        additionalTokenClaims,
                        PUBLIC_SUBJECT,
                        INTERNAL_PAIRWISE_SUBJECT,
                        null,
                        false,
                        JWSAlgorithm.ES256,
                        JOURNEY_ID,
                        VOT,
                        AUTH_TIME,
                        AUTH_CODE);

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
        OIDCTokenResponse tokenResponse =
                tokenService.generateTokenResponse(
                        CLIENT_ID,
                        SCOPES_OFFLINE_ACCESS,
                        additionalTokenClaims,
                        PUBLIC_SUBJECT,
                        INTERNAL_PAIRWISE_SUBJECT,
                        null,
                        false,
                        JWSAlgorithm.ES256,
                        JOURNEY_ID,
                        VOT,
                        AUTH_TIME,
                        AUTH_CODE);

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

        assertTrue(errorObject.isPresent());
        assertThat(
                errorObject.get(),
                samePropertyValuesAs(
                        new ErrorObject(
                                OAuth2Error.INVALID_REQUEST_CODE,
                                "Request is missing redirect_uri parameter")));
    }

    @Test
    void shouldReturnErrorIfGrantTypeIsMissingWhenValidatingTokenRequest() {
        Map<String, List<String>> customParams = new HashMap<>();
        customParams.put("client_id", Collections.singletonList(CLIENT_ID));
        customParams.put("code", Collections.singletonList(AUTH_CODE));
        customParams.put("redirect_uri", Collections.singletonList(REDIRECT_URI));
        Optional<ErrorObject> errorObject =
                tokenService.validateTokenRequestParams(URLUtils.serializeParameters(customParams));

        assertTrue(errorObject.isPresent());
        assertThat(
                errorObject.get(),
                samePropertyValuesAs(
                        new ErrorObject(
                                OAuth2Error.INVALID_REQUEST_CODE,
                                "Request is missing grant_type parameter")));
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

        assertTrue(errorObject.isPresent());
        assertThat(
                errorObject.get(),
                samePropertyValuesAs(
                        new ErrorObject(
                                OAuth2Error.INVALID_REQUEST_CODE,
                                "Request is missing code parameter")));
    }

    @Test
    void shouldReturnErrorIfCodeIEmptyStringWhenValidatingTokenRequest() {
        Map<String, List<String>> customParams = new HashMap<>();
        customParams.put(
                "grant_type", Collections.singletonList(GrantType.AUTHORIZATION_CODE.getValue()));
        customParams.put("client_id", Collections.singletonList(CLIENT_ID));
        customParams.put("redirect_uri", Collections.singletonList(REDIRECT_URI));
        customParams.put("code", Collections.singletonList(""));
        Optional<ErrorObject> errorObject =
                tokenService.validateTokenRequestParams(URLUtils.serializeParameters(customParams));

        assertTrue(errorObject.isPresent());
        assertThat(
                errorObject.get(),
                samePropertyValuesAs(
                        new ErrorObject(
                                OAuth2Error.INVALID_REQUEST_CODE,
                                "Request is missing code parameter")));
    }

    @Test
    void shouldReturnErrorIfCodeIsNullWhenValidatingTokenRequest() {
        var requestBody =
                "grant_type="
                        + GrantType.AUTHORIZATION_CODE.getValue()
                        + "&client_id="
                        + CLIENT_ID
                        + "&redirect_uri="
                        + REDIRECT_URI
                        + "&code";
        Optional<ErrorObject> errorObject = tokenService.validateTokenRequestParams(requestBody);

        assertTrue(errorObject.isPresent());
        assertThat(
                errorObject.get(),
                samePropertyValuesAs(
                        new ErrorObject(
                                OAuth2Error.INVALID_REQUEST_CODE,
                                "Request is missing code parameter")));
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

    @Test
    void shouldGenerateNewTokensFromRefreshToken() throws Exception {
        var scopes = List.of("openid", "offline_access");
        var clientSessionId = "test-client-session-id";
        createSignedAccessToken();

        tokenService.generateRefreshTokenResponse(
                CLIENT_ID,
                scopes,
                PUBLIC_SUBJECT,
                INTERNAL_PAIRWISE_SUBJECT,
                JWSAlgorithm.ES256,
                AUTH_CODE,
                clientSessionId);

        verify(orchAccessTokenService)
                .saveAccessToken(
                        eq(CLIENT_ID + "." + PUBLIC_SUBJECT.getValue()),
                        eq(AUTH_CODE),
                        anyString(),
                        eq(INTERNAL_PAIRWISE_SUBJECT.getValue()),
                        eq(clientSessionId));
        verify(orchRefreshTokenService)
                .saveRefreshToken(
                        anyString(),
                        eq(INTERNAL_PAIRWISE_SUBJECT.getValue()),
                        anyString(),
                        eq(AUTH_CODE),
                        eq(clientSessionId));
    }

    @Nested
    class KeyRotation {

        private final String NEW_KEY_ALIAS = "alias/new-signing-key";
        private final String NEW_KEY_ALIAS_RSA = "alias/new-signing-key-rsa";

        private final String PREVIOUS_KEY_ALIAS = "alias/old-signing-key";
        private final String PREVIOUS_KEY_ALIAS_RSA = "alias/old-signing-key-rsa";

        private final String MOCK_PREVIOUS_EC_KEY_ID =
                "nF2rpzCc-UZavTfpb9V7TTBG4uphYul9u-Op-cLqf_4";
        private final String MOCK_PREVIOUS_RSA_KEY_ID =
                "A67fuGRkM96UF0YRCObJMeRLfL38jAP07zAAv79uYRk";

        private final String EXPECTED_OPAQUE_PREVIOUS_EC_KEY_ID =
                hashSha256String(MOCK_PREVIOUS_EC_KEY_ID);
        private final String EXPECTED_OPAQUE_PREVIOUS_RSA_KEY_ID =
                hashSha256String(MOCK_PREVIOUS_RSA_KEY_ID);

        private final String MOCK_SIGNATURE =
                "f1pIGJZixTCGckjMnnAJM7efIPCJF177FqsenqflVXRQPa-FE-5viRrgPXdTjlDShFOwOQEfF6c8IlBixzorPA";

        private final String MOCK_NEW_EC_KEY_ID = "i4rwnl-SLuhPjdtP1GJyKXZRDG00znaRld8sSArsToM";
        private final String MOCK_NEW_RSA_KEY_ID = "LA9hmMyeZ2h4oOZcoWpReQKHGp0PwfyzuKCce68xpxs";

        private final String EXPECTED_OPAQUE_NEW_EC_KEY_ID = hashSha256String(MOCK_NEW_EC_KEY_ID);
        private final String EXPECTED_OPAQUE_NEW_RSA_KEY_ID = hashSha256String(MOCK_NEW_RSA_KEY_ID);

        private SignResponse mockSignResponseRsa;
        private SignResponse mockSignResponseEc;

        @BeforeEach
        void setup() throws JOSEException {

            when(configurationService.getExternalTokenSigningKeyAlias())
                    .thenReturn(PREVIOUS_KEY_ALIAS);
            when(configurationService.getExternalTokenSigningKeyRsaAlias())
                    .thenReturn(PREVIOUS_KEY_ALIAS_RSA);

            when(kmsConnectionService.getPublicKey(
                            GetPublicKeyRequest.builder().keyId(PREVIOUS_KEY_ALIAS).build()))
                    .thenReturn(
                            GetPublicKeyResponse.builder().keyId(MOCK_PREVIOUS_EC_KEY_ID).build());
            when(kmsConnectionService.getPublicKey(
                            GetPublicKeyRequest.builder().keyId(PREVIOUS_KEY_ALIAS_RSA).build()))
                    .thenReturn(
                            GetPublicKeyResponse.builder().keyId(MOCK_PREVIOUS_RSA_KEY_ID).build());

            when(configurationService.getNextExternalTokenSigningKeyAlias())
                    .thenReturn(NEW_KEY_ALIAS);
            when(configurationService.getNextExternalTokenSigningKeyRsaAlias())
                    .thenReturn(NEW_KEY_ALIAS_RSA);

            when(kmsConnectionService.getPublicKey(
                            GetPublicKeyRequest.builder().keyId(NEW_KEY_ALIAS).build()))
                    .thenReturn(GetPublicKeyResponse.builder().keyId(MOCK_NEW_EC_KEY_ID).build());
            when(kmsConnectionService.getPublicKey(
                            GetPublicKeyRequest.builder().keyId(NEW_KEY_ALIAS_RSA).build()))
                    .thenReturn(GetPublicKeyResponse.builder().keyId(MOCK_NEW_RSA_KEY_ID).build());

            when(kmsConnectionService.getPublicKey(
                            GetPublicKeyRequest.builder().keyId(KEY_ID).build()))
                    .thenReturn(GetPublicKeyResponse.builder().keyId(MOCK_NEW_EC_KEY_ID).build());
            when(kmsConnectionService.getPublicKey(
                            GetPublicKeyRequest.builder().keyId(NEW_KEY_ALIAS_RSA).build()))
                    .thenReturn(GetPublicKeyResponse.builder().keyId(MOCK_NEW_RSA_KEY_ID).build());

            mockSignResponseEc =
                    SignResponse.builder()
                            .signature(
                                    SdkBytes.fromByteArray(
                                            ECDSA.transcodeSignatureToDER(
                                                    MOCK_SIGNATURE.getBytes(
                                                            StandardCharsets.UTF_8))))
                            .build();
            mockSignResponseRsa =
                    SignResponse.builder()
                            .signature(
                                    SdkBytes.fromByteArray(
                                            MOCK_SIGNATURE.getBytes(StandardCharsets.UTF_8)))
                            .build();
        }

        @Test
        void itShouldUseTheNewKeyToCreateATokenWhenFeatureFlagEnabled() {
            when(configurationService.isUseNewTokenSigningKeysEnabled()).thenReturn(true);
            when(kmsConnectionService.sign(any(SignRequest.class))).thenReturn(mockSignResponseEc);

            var testClaimsSet =
                    new JWTClaimsSet.Builder()
                            .claim("sub", FIXED_INTERNAL_PAIRWISE_SUBJECT)
                            .build();

            var signedToken =
                    tokenService.generateSignedJwtUsingExternalKey(
                            testClaimsSet, Optional.empty(), JWSAlgorithm.ES256);

            verify(kmsConnectionService)
                    .getPublicKey(GetPublicKeyRequest.builder().keyId(NEW_KEY_ALIAS).build());
            assertThat(signedToken.getHeader().getAlgorithm(), equalTo(JWSAlgorithm.ES256));
            assertThat(signedToken.getHeader().getKeyID(), equalTo(EXPECTED_OPAQUE_NEW_EC_KEY_ID));
        }

        @Test
        void itShouldUseTheNewRsaKeyToCreateATokenWhenFeatureFlagEnabled() {
            when(configurationService.isUseNewTokenSigningKeysEnabled()).thenReturn(true);
            when(kmsConnectionService.sign(any(SignRequest.class))).thenReturn(mockSignResponseRsa);

            var testClaimsSet =
                    new JWTClaimsSet.Builder()
                            .claim("sub", FIXED_INTERNAL_PAIRWISE_SUBJECT)
                            .build();

            var signedToken =
                    tokenService.generateSignedJwtUsingExternalKey(
                            testClaimsSet, Optional.empty(), JWSAlgorithm.RS256);

            verify(kmsConnectionService)
                    .getPublicKey(GetPublicKeyRequest.builder().keyId(NEW_KEY_ALIAS_RSA).build());
            assertThat(signedToken.getHeader().getAlgorithm(), equalTo(JWSAlgorithm.RS256));
            assertThat(signedToken.getHeader().getKeyID(), equalTo(EXPECTED_OPAQUE_NEW_RSA_KEY_ID));
        }

        @Test
        void itShouldContinueToUseOldKeyWhenFeatureFlagIsDisabled() {
            when(configurationService.isUseNewTokenSigningKeysEnabled()).thenReturn(false);
            when(kmsConnectionService.sign(any(SignRequest.class))).thenReturn(mockSignResponseEc);

            var testClaimsSet =
                    new JWTClaimsSet.Builder()
                            .claim("sub", FIXED_INTERNAL_PAIRWISE_SUBJECT)
                            .build();

            var signedToken =
                    tokenService.generateSignedJwtUsingExternalKey(
                            testClaimsSet, Optional.empty(), JWSAlgorithm.ES256);

            verify(kmsConnectionService)
                    .getPublicKey(GetPublicKeyRequest.builder().keyId(PREVIOUS_KEY_ALIAS).build());
            assertThat(signedToken.getHeader().getAlgorithm(), equalTo(JWSAlgorithm.ES256));
            assertThat(
                    signedToken.getHeader().getKeyID(),
                    equalTo(EXPECTED_OPAQUE_PREVIOUS_EC_KEY_ID));
        }

        @Test
        void itShouldContinueToUseOldRsaKeyWhenFeatureFlagIsDisabled() {
            when(configurationService.isUseNewTokenSigningKeysEnabled()).thenReturn(false);
            when(kmsConnectionService.sign(any(SignRequest.class))).thenReturn(mockSignResponseRsa);

            var testClaimsSet =
                    new JWTClaimsSet.Builder()
                            .claim("sub", FIXED_INTERNAL_PAIRWISE_SUBJECT)
                            .build();

            var signedToken =
                    tokenService.generateSignedJwtUsingExternalKey(
                            testClaimsSet, Optional.empty(), JWSAlgorithm.RS256);

            verify(kmsConnectionService)
                    .getPublicKey(
                            GetPublicKeyRequest.builder().keyId(PREVIOUS_KEY_ALIAS_RSA).build());
            assertThat(signedToken.getHeader().getAlgorithm(), equalTo(JWSAlgorithm.RS256));
            assertThat(
                    signedToken.getHeader().getKeyID(),
                    equalTo(EXPECTED_OPAQUE_PREVIOUS_RSA_KEY_ID));
        }
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
                CLIENT_ID, PUBLIC_SUBJECT, OIDC_BASE_URI, ecSigningKey, expiryDate);
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
                        OIDC_BASE_URI,
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
            throws ParseException {

        verify(orchAccessTokenService)
                .saveAccessToken(
                        CLIENT_ID + "." + PUBLIC_SUBJECT.getValue(),
                        AUTH_CODE,
                        tokenResponse.getOIDCTokens().getAccessToken().getValue(),
                        INTERNAL_PAIRWISE_SUBJECT.getValue(),
                        JOURNEY_ID);

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
                equalTo(buildURI(OIDC_BASE_URI, "/trustmark").toString()));
        assertThat(
                tokenResponse.getOIDCTokens().getIDToken().getJWTClaimsSet().getIssuer(),
                equalTo(OIDC_BASE_URI));
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
                is(JOURNEY_ID));
        assertThat(
                tokenResponse.getOIDCTokens().getIDToken().getJWTClaimsSet().getClaim("auth_time"),
                is(AUTH_TIME));
    }
}
