package uk.gov.di.authentication.api;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.google.gson.Gson;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.auth.ClientSecretPost;
import com.nimbusds.oauth2.sdk.auth.JWTAuthenticationClaimsSet;
import com.nimbusds.oauth2.sdk.auth.PrivateKeyJWT;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.JWTID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.pkce.CodeChallenge;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.oauth2.sdk.token.Tokens;
import com.nimbusds.oauth2.sdk.util.JSONArrayUtils;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.oauth2.sdk.util.URLUtils;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCClaimsRequest;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.SubjectType;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSetRequest;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.authentication.oidc.lambda.TokenHandler;
import uk.gov.di.orchestration.shared.entity.OrchClientSessionItem;
import uk.gov.di.orchestration.shared.entity.OrchRefreshTokenItem;
import uk.gov.di.orchestration.shared.entity.VectorOfTrust;
import uk.gov.di.orchestration.shared.helpers.IdGenerator;
import uk.gov.di.orchestration.shared.helpers.NowHelper;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;
import uk.gov.di.orchestration.sharedtest.extensions.OrchAccessTokenExtension;
import uk.gov.di.orchestration.sharedtest.extensions.OrchAuthCodeExtension;
import uk.gov.di.orchestration.sharedtest.extensions.OrchClientSessionExtension;
import uk.gov.di.orchestration.sharedtest.extensions.OrchRefreshTokenExtension;
import uk.gov.di.orchestration.sharedtest.extensions.RpPublicKeyCacheExtension;
import uk.gov.di.orchestration.sharedtest.helper.AuditAssertionsHelper;
import uk.gov.di.orchestration.sharedtest.helper.JsonArrayHelper;
import uk.gov.di.orchestration.sharedtest.utils.KeyPairUtils;

import java.net.URI;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import static com.nimbusds.jose.JWSAlgorithm.ES256;
import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.orchestration.shared.domain.TokenGeneratedAuditableEvent.OIDC_TOKEN_GENERATED;
import static uk.gov.di.orchestration.shared.entity.IdentityClaims.VOT;
import static uk.gov.di.orchestration.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasBody;
import static uk.gov.di.orchestration.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

public class TokenIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    private static final String TOKEN_ENDPOINT = "/token";
    private static final String TEST_EMAIL = "joe.bloggs@digital.cabinet-office.gov.uk";
    private static final String CLIENT_ID = "test-id";
    private static final String DIFFERENT_CLIENT_ID = "different-test-id";
    private static final String INTERNAL_PAIRWISE_SUBJECT_ID = "internal-pairwise-subject-id";
    private static final String RP_PAIRWISE_ID = "rp-pairwise-id";
    private static final String PUBLIC_SUBJECT_ID = "public-subject-id";
    private static final String AUTH_CODE = "test-auth-code";
    private static final String REDIRECT_URI = "http://localhost/redirect";
    private static final Long AUTH_TIME = NowHelper.now().toInstant().getEpochSecond() - 120L;
    private final CodeVerifier CODE_VERIFIER = new CodeVerifier();
    private final String CODE_CHALLENGE_STRING = createCodeChallengeFromCodeVerifier(CODE_VERIFIER);
    private static final String CLIENT_SESSION_ID = "a-client-session-id";

    protected static final ConfigurationService configuration =
            new IntegrationTestConfigurationService(
                    externalTokenSigner,
                    storageTokenSigner,
                    ipvPrivateKeyJwtSigner,
                    spotQueue,
                    docAppPrivateKeyJwtSigner,
                    configurationParameters) {

                @Override
                public String getTxmaAuditQueueUrl() {
                    return txmaAuditQueue.getQueueUrl();
                }
            };

    @RegisterExtension
    public static final RpPublicKeyCacheExtension rpPublicKeyCacheExtension =
            new RpPublicKeyCacheExtension(180);

    @RegisterExtension
    public static final OrchClientSessionExtension orchClientSessionExtension =
            new OrchClientSessionExtension();

    @RegisterExtension
    public static final OrchAuthCodeExtension orchAuthCodeExtension = new OrchAuthCodeExtension();

    @RegisterExtension
    public static final OrchAccessTokenExtension orchAccessTokenExtension =
            new OrchAccessTokenExtension();

    @RegisterExtension
    public static final OrchRefreshTokenExtension orchRefreshTokenExtension =
            new OrchRefreshTokenExtension();

    @BeforeEach
    void setup() {
        handler = new TokenHandler(configuration, redisConnectionService);
        txmaAuditQueue.clear();
    }

    private static Stream<Arguments> validVectorValues() {
        return Stream.of(
                Arguments.of(Optional.of("Cl.Cm"), "Cl.Cm", Optional.of(CLIENT_ID)),
                Arguments.of(Optional.of("Cl"), "Cl", Optional.of(CLIENT_ID)),
                Arguments.of(Optional.of("P2.Cl.Cm"), "Cl.Cm", Optional.of(CLIENT_ID)),
                Arguments.of(Optional.empty(), "Cl.Cm", Optional.of(CLIENT_ID)),
                Arguments.of(Optional.of("Cl.Cm"), "Cl.Cm", Optional.empty()),
                Arguments.of(Optional.of("Cl"), "Cl", Optional.empty()),
                Arguments.of(Optional.of("P2.Cl.Cm"), "Cl.Cm", Optional.empty()),
                Arguments.of(Optional.empty(), "Cl.Cm", Optional.empty()));
    }

    @ParameterizedTest
    @MethodSource("validVectorValues")
    void shouldCallTokenResourceAndReturnAccessAndRefreshTokenWhenAuthenticatingWithPrivateKeyJwt(
            Optional<String> vtr, String expectedVotClaim, Optional<String> clientId)
            throws Exception {
        KeyPair keyPair = KeyPairUtils.generateRsaKeyPair();
        Scope scope =
                new Scope(
                        OIDCScopeValue.OPENID.getValue(), OIDCScopeValue.OFFLINE_ACCESS.getValue());
        registerClientWithPrivateKeyJwtAuthentication(
                keyPair.getPublic(), scope, SubjectType.PAIRWISE);
        var baseTokenRequest = constructBaseTokenRequest(scope, vtr, Optional.empty(), clientId);
        var response = makeTokenRequestWithPrivateKeyJWT(baseTokenRequest, keyPair.getPrivate());

        assertThat(response, hasStatus(200));
        JSONObject jsonResponse = JSONObjectUtils.parse(response.getBody());
        assertNotNull(
                TokenResponse.parse(jsonResponse)
                        .toSuccessResponse()
                        .getTokens()
                        .getRefreshToken());
        assertNotNull(
                TokenResponse.parse(jsonResponse)
                        .toSuccessResponse()
                        .getTokens()
                        .getBearerAccessToken());

        var idToken = OIDCTokenResponse.parse(jsonResponse).getOIDCTokens().getIDToken();
        assertThat(idToken.getJWTClaimsSet().getClaim(VOT.getValue()), equalTo(expectedVotClaim));

        AuditAssertionsHelper.assertTxmaAuditEventsReceived(
                txmaAuditQueue, List.of(OIDC_TOKEN_GENERATED));

        var orchClientSession = orchClientSessionExtension.getClientSession(CLIENT_SESSION_ID);
        assertTrue(orchClientSession.isPresent());
        assertEquals(idToken.serialize(), orchClientSession.get().getIdTokenHint());
    }

    @Test
    void shouldAllowIssuerUriAsPrivateKeyJwtAudience() throws Exception {
        KeyPair keyPair = KeyPairUtils.generateRsaKeyPair();
        Scope scope =
                new Scope(
                        OIDCScopeValue.OPENID.getValue(), OIDCScopeValue.OFFLINE_ACCESS.getValue());
        registerClientWithPrivateKeyJwtAuthentication(
                keyPair.getPublic(), scope, SubjectType.PAIRWISE);
        var baseTokenRequest =
                constructBaseTokenRequest(
                        scope, Optional.of("Cl.Cm"), Optional.empty(), Optional.of(CLIENT_ID));

        var response =
                makeTokenRequestWithPrivateKeyJWT(
                        CLIENT_ID,
                        baseTokenRequest,
                        keyPair.getPrivate(),
                        new Audience(ROOT_RESOURCE_URL).toSingleAudienceList());

        assertThat(response, hasStatus(200));
        JSONObject jsonResponse = JSONObjectUtils.parse(response.getBody());
        assertNotNull(
                TokenResponse.parse(jsonResponse)
                        .toSuccessResponse()
                        .getTokens()
                        .getRefreshToken());
        assertNotNull(
                TokenResponse.parse(jsonResponse)
                        .toSuccessResponse()
                        .getTokens()
                        .getBearerAccessToken());

        var idToken = OIDCTokenResponse.parse(jsonResponse).getOIDCTokens().getIDToken();
        assertThat(idToken.getJWTClaimsSet().getClaim(VOT.getValue()), equalTo("Cl.Cm"));

        AuditAssertionsHelper.assertTxmaAuditEventsReceived(
                txmaAuditQueue, List.of(OIDC_TOKEN_GENERATED));

        var orchClientSession = orchClientSessionExtension.getClientSession(CLIENT_SESSION_ID);
        assertTrue(orchClientSession.isPresent());
        assertEquals(idToken.serialize(), orchClientSession.get().getIdTokenHint());
    }

    @Test
    void shouldReturn200WithTokensWhenPrivateKeyJwtContainsBothIssuerAndTokenURIAsAudienceList()
            throws Exception {
        KeyPair keyPair = KeyPairUtils.generateRsaKeyPair();
        Scope scope =
                new Scope(
                        OIDCScopeValue.OPENID.getValue(), OIDCScopeValue.OFFLINE_ACCESS.getValue());
        registerClientWithPrivateKeyJwtAuthentication(
                keyPair.getPublic(), scope, SubjectType.PAIRWISE);
        var baseTokenRequest =
                constructBaseTokenRequest(
                        scope, Optional.of("Cl.Cm"), Optional.empty(), Optional.of(CLIENT_ID));

        var response =
                makeTokenRequestWithPrivateKeyJWT(
                        CLIENT_ID,
                        baseTokenRequest,
                        keyPair.getPrivate(),
                        List.of(
                                new Audience(ROOT_RESOURCE_URL),
                                new Audience(ROOT_RESOURCE_URL + TOKEN_ENDPOINT)));

        assertThat(response, hasStatus(200));
        JSONObject jsonResponse = JSONObjectUtils.parse(response.getBody());
        assertNotNull(
                TokenResponse.parse(jsonResponse)
                        .toSuccessResponse()
                        .getTokens()
                        .getRefreshToken());
        assertNotNull(
                TokenResponse.parse(jsonResponse)
                        .toSuccessResponse()
                        .getTokens()
                        .getBearerAccessToken());

        var idToken = OIDCTokenResponse.parse(jsonResponse).getOIDCTokens().getIDToken();
        assertThat(idToken.getJWTClaimsSet().getClaim(VOT.getValue()), equalTo("Cl.Cm"));

        AuditAssertionsHelper.assertTxmaAuditEventsReceived(
                txmaAuditQueue, List.of(OIDC_TOKEN_GENERATED));

        var orchClientSession = orchClientSessionExtension.getClientSession(CLIENT_SESSION_ID);
        assertTrue(orchClientSession.isPresent());
        assertEquals(idToken.serialize(), orchClientSession.get().getIdTokenHint());
    }

    @Test
    void
            shouldCallTokenResourceAndReturnAccessAndRefreshTokenWhenAuthenticatingWithClientSecretPost()
                    throws Exception {
        var clientSecret = new Secret();
        var scope =
                new Scope(
                        OIDCScopeValue.OPENID.getValue(), OIDCScopeValue.OFFLINE_ACCESS.getValue());
        registerClientSecretClient(
                clientSecret.getValue(), ClientAuthenticationMethod.CLIENT_SECRET_POST, scope);
        var baseTokenRequest =
                constructBaseTokenRequest(
                        scope, Optional.of("Cl.Cm"), Optional.empty(), Optional.of(CLIENT_ID));
        var response = makeTokenRequestWithClientSecretPost(baseTokenRequest, clientSecret);

        assertThat(response, hasStatus(200));
        var jsonResponse = JSONObjectUtils.parse(response.getBody());
        assertNotNull(
                TokenResponse.parse(jsonResponse)
                        .toSuccessResponse()
                        .getTokens()
                        .getRefreshToken());
        assertNotNull(
                TokenResponse.parse(jsonResponse)
                        .toSuccessResponse()
                        .getTokens()
                        .getBearerAccessToken());

        assertThat(
                OIDCTokenResponse.parse(jsonResponse)
                        .getOIDCTokens()
                        .getIDToken()
                        .getJWTClaimsSet()
                        .getClaim(VOT.getValue()),
                equalTo("Cl.Cm"));

        AuditAssertionsHelper.assertTxmaAuditEventsReceived(
                txmaAuditQueue, List.of(OIDC_TOKEN_GENERATED));
    }

    @Test
    void shouldCallTokenResourceAndReturn400WhenClientIdParameterDoesNotMatch() throws Exception {
        KeyPair keyPair = KeyPairUtils.generateRsaKeyPair();
        Scope scope =
                new Scope(
                        OIDCScopeValue.OPENID.getValue(), OIDCScopeValue.OFFLINE_ACCESS.getValue());
        registerClientWithPrivateKeyJwtAuthentication(
                keyPair.getPublic(), scope, SubjectType.PAIRWISE);
        var baseTokenRequest =
                constructBaseTokenRequest(
                        scope,
                        Optional.of("Cl.Cm"),
                        Optional.empty(),
                        Optional.of(DIFFERENT_CLIENT_ID));

        var response = makeTokenRequestWithPrivateKeyJWT(baseTokenRequest, keyPair.getPrivate());

        assertThat(response, hasStatus(400));
        assertThat(
                response,
                hasBody(
                        new ErrorObject(OAuth2Error.INVALID_REQUEST_CODE, "Invalid private_key_jwt")
                                .toJSONObject()
                                .toJSONString()));
    }

    @Test
    void shouldReturnIdTokenWithPublicSubjectId() throws Exception {
        KeyPair keyPair = KeyPairUtils.generateRsaKeyPair();
        Scope scope =
                new Scope(
                        OIDCScopeValue.OPENID.getValue(), OIDCScopeValue.OFFLINE_ACCESS.getValue());
        registerClientWithPrivateKeyJwtAuthentication(
                keyPair.getPublic(), scope, SubjectType.PUBLIC);
        var baseTokenRequest =
                constructBaseTokenRequest(
                        scope, Optional.empty(), Optional.empty(), Optional.of(CLIENT_ID));

        var response = makeTokenRequestWithPrivateKeyJWT(baseTokenRequest, keyPair.getPrivate());

        assertThat(response, hasStatus(200));
        JSONObject jsonResponse = JSONObjectUtils.parse(response.getBody());
        var idTokenClaims =
                OIDCTokenResponse.parse(jsonResponse)
                        .getOIDCTokens()
                        .getIDToken()
                        .getJWTClaimsSet();

        assertNotNull(
                TokenResponse.parse(jsonResponse)
                        .toSuccessResponse()
                        .getTokens()
                        .getRefreshToken());
        assertNotNull(
                TokenResponse.parse(jsonResponse)
                        .toSuccessResponse()
                        .getTokens()
                        .getBearerAccessToken());
        assertThat(idTokenClaims.getSubject(), equalTo(PUBLIC_SUBJECT_ID));
        assertThat(idTokenClaims.getClaim("auth_time"), equalTo(AUTH_TIME));

        AuditAssertionsHelper.assertTxmaAuditEventsReceived(
                txmaAuditQueue, List.of(OIDC_TOKEN_GENERATED));
    }

    @Test
    void shouldReturnIdTokenWithPairwiseSubjectId() throws Exception {
        KeyPair keyPair = KeyPairUtils.generateRsaKeyPair();
        Scope scope =
                new Scope(
                        OIDCScopeValue.OPENID.getValue(), OIDCScopeValue.OFFLINE_ACCESS.getValue());
        registerClientWithPrivateKeyJwtAuthentication(
                keyPair.getPublic(), scope, SubjectType.PAIRWISE);
        var baseTokenRequest =
                constructBaseTokenRequest(
                        scope, Optional.empty(), Optional.empty(), Optional.of(CLIENT_ID));

        var response = makeTokenRequestWithPrivateKeyJWT(baseTokenRequest, keyPair.getPrivate());

        assertThat(response, hasStatus(200));
        JSONObject jsonResponse = JSONObjectUtils.parse(response.getBody());
        var idTokenClaims =
                OIDCTokenResponse.parse(jsonResponse)
                        .getOIDCTokens()
                        .getIDToken()
                        .getJWTClaimsSet();
        assertNotNull(
                TokenResponse.parse(jsonResponse)
                        .toSuccessResponse()
                        .getTokens()
                        .getRefreshToken());
        assertNotNull(
                TokenResponse.parse(jsonResponse)
                        .toSuccessResponse()
                        .getTokens()
                        .getBearerAccessToken());
        assertThat(idTokenClaims.getSubject(), equalTo(RP_PAIRWISE_ID));
        assertThat(idTokenClaims.getClaim("auth_time"), equalTo(AUTH_TIME));

        AuditAssertionsHelper.assertTxmaAuditEventsReceived(
                txmaAuditQueue, List.of(OIDC_TOKEN_GENERATED));
    }

    @Test
    void shouldCallTokenResourceAndReturnIdentityClaims() throws Exception {
        KeyPair keyPair = KeyPairUtils.generateRsaKeyPair();
        Scope scope = new Scope(OIDCScopeValue.OPENID.getValue());
        var claimsSetRequest = new ClaimsSetRequest().add("nickname").add("birthdate");
        var oidcClaimsRequest = new OIDCClaimsRequest().withUserInfoClaimsRequest(claimsSetRequest);
        registerClientWithPrivateKeyJwtAuthentication(
                keyPair.getPublic(), scope, SubjectType.PAIRWISE);
        var baseTokenRequest =
                constructBaseTokenRequest(
                        scope,
                        Optional.of("P2.Cl.Cm"),
                        Optional.of(oidcClaimsRequest),
                        Optional.of(CLIENT_ID));

        var response = makeTokenRequestWithPrivateKeyJWT(baseTokenRequest, keyPair.getPrivate());

        assertThat(response, hasStatus(200));
        JSONObject jsonResponse = JSONObjectUtils.parse(response.getBody());
        assertNull(
                TokenResponse.parse(jsonResponse)
                        .toSuccessResponse()
                        .getTokens()
                        .getRefreshToken());
        assertNotNull(
                TokenResponse.parse(jsonResponse)
                        .toSuccessResponse()
                        .getTokens()
                        .getBearerAccessToken());
        BearerAccessToken bearerAccessToken =
                TokenResponse.parse(jsonResponse)
                        .toSuccessResponse()
                        .getTokens()
                        .getBearerAccessToken();
        JSONArray jsonarray =
                JSONArrayUtils.parse(
                        new Gson()
                                .toJson(
                                        SignedJWT.parse(bearerAccessToken.getValue())
                                                .getJWTClaimsSet()
                                                .getClaim("claims")));

        assertTrue(jsonarray.contains("nickname"));
        assertTrue(jsonarray.contains("birthdate"));
        AuditAssertionsHelper.assertTxmaAuditEventsReceived(
                txmaAuditQueue, List.of(OIDC_TOKEN_GENERATED));
    }

    @Test
    void shouldCallTokenResourceAndOnlyReturnAccessTokenWithoutOfflineAccessScope()
            throws Exception {
        KeyPair keyPair = KeyPairUtils.generateRsaKeyPair();
        Scope scope = new Scope(OIDCScopeValue.OPENID.getValue());
        registerClientWithPrivateKeyJwtAuthentication(
                keyPair.getPublic(), scope, SubjectType.PAIRWISE);
        var baseTokenRequest =
                constructBaseTokenRequest(
                        scope, Optional.empty(), Optional.empty(), Optional.of(CLIENT_ID));

        var response = makeTokenRequestWithPrivateKeyJWT(baseTokenRequest, keyPair.getPrivate());

        assertThat(response, hasStatus(200));
        JSONObject jsonResponse = JSONObjectUtils.parse(response.getBody());
        assertNull(
                TokenResponse.parse(jsonResponse)
                        .toSuccessResponse()
                        .getTokens()
                        .getRefreshToken());
        assertNotNull(
                TokenResponse.parse(jsonResponse)
                        .toSuccessResponse()
                        .getTokens()
                        .getBearerAccessToken());

        AuditAssertionsHelper.assertTxmaAuditEventsReceived(
                txmaAuditQueue, List.of(OIDC_TOKEN_GENERATED));
    }

    @Test
    void shouldCallTokenResourceWithRefreshTokenGrantAndReturn200() throws Exception {
        Scope scope =
                new Scope(
                        OIDCScopeValue.OPENID, OIDCScopeValue.EMAIL, OIDCScopeValue.OFFLINE_ACCESS);
        Subject publicSubject = new Subject();
        KeyPair keyPair = KeyPairUtils.generateRsaKeyPair();
        registerClientWithPrivateKeyJwtAuthentication(
                keyPair.getPublic(), scope, SubjectType.PAIRWISE);
        SignedJWT signedJWT = generateSignedRefreshToken(scope, publicSubject);
        RefreshToken refreshToken = new RefreshToken(signedJWT.serialize());
        orchRefreshTokenExtension.saveRefreshToken(
                signedJWT.getJWTClaimsSet().getJWTID(),
                INTERNAL_PAIRWISE_SUBJECT_ID,
                refreshToken.getValue(),
                AUTH_CODE);

        PrivateKey privateKey = keyPair.getPrivate();
        JWTAuthenticationClaimsSet claimsSet =
                new JWTAuthenticationClaimsSet(
                        new ClientID(CLIENT_ID), new Audience(ROOT_RESOURCE_URL + TOKEN_ENDPOINT));
        var expiryDate = NowHelper.nowPlus(5, ChronoUnit.MINUTES);
        claimsSet.getExpirationTime().setTime(expiryDate.getTime());
        var privateKeyJWT =
                new PrivateKeyJWT(claimsSet, JWSAlgorithm.RS256, privateKey, null, null);
        Map<String, List<String>> customParams = new HashMap<>();
        customParams.put(
                "grant_type", Collections.singletonList(GrantType.REFRESH_TOKEN.getValue()));
        customParams.put("client_id", Collections.singletonList(CLIENT_ID));
        customParams.put("refresh_token", Collections.singletonList(refreshToken.getValue()));
        Map<String, List<String>> privateKeyParams = privateKeyJWT.toParameters();
        privateKeyParams.putAll(customParams);
        String requestParams = URLUtils.serializeParameters(privateKeyParams);
        var response = makeRequest(Optional.of(requestParams), Map.of(), Map.of());

        assertThat(response, hasStatus(200));
        JSONObject jsonResponse = JSONObjectUtils.parse(response.getBody());

        Tokens tokens = TokenResponse.parse(jsonResponse).toSuccessResponse().getTokens();
        assertNotNull(tokens.getRefreshToken());
        assertNotNull(tokens.getBearerAccessToken());
        String jwtId =
                SignedJWT.parse(tokens.getRefreshToken().getValue()).getJWTClaimsSet().getJWTID();
        Optional<OrchRefreshTokenItem> orchRefreshTokenItem =
                orchRefreshTokenExtension.getRefreshToken(jwtId);
        assertTrue(orchRefreshTokenItem.isPresent());
        assertEquals(
                INTERNAL_PAIRWISE_SUBJECT_ID,
                orchRefreshTokenItem.get().getInternalPairwiseSubjectId());
        assertEquals(AUTH_CODE, orchRefreshTokenItem.get().getAuthCode());
        assertEquals(tokens.getRefreshToken().getValue(), orchRefreshTokenItem.get().getToken());

        AuditAssertionsHelper.assertNoTxmaAuditEventsReceived(txmaAuditQueue);
    }

    @Test
    void shouldCallTokenResourceWithRefreshTokenGrantAndMissingInternalPairwiseIdAndReturn200()
            throws Exception {
        Scope scope =
                new Scope(
                        OIDCScopeValue.OPENID, OIDCScopeValue.EMAIL, OIDCScopeValue.OFFLINE_ACCESS);
        Subject publicSubject = new Subject();
        KeyPair keyPair = KeyPairUtils.generateRsaKeyPair();
        registerClientWithPrivateKeyJwtAuthentication(
                keyPair.getPublic(), scope, SubjectType.PAIRWISE);
        SignedJWT signedJWT = generateSignedRefreshToken(scope, publicSubject);
        RefreshToken refreshToken = new RefreshToken(signedJWT.serialize());
        orchRefreshTokenExtension.saveRefreshToken(
                signedJWT.getJWTClaimsSet().getJWTID(),
                INTERNAL_PAIRWISE_SUBJECT_ID,
                refreshToken.getValue(),
                AUTH_CODE);
        PrivateKey privateKey = keyPair.getPrivate();
        JWTAuthenticationClaimsSet claimsSet =
                new JWTAuthenticationClaimsSet(
                        new ClientID(CLIENT_ID), new Audience(ROOT_RESOURCE_URL + TOKEN_ENDPOINT));
        var expiryDate = NowHelper.nowPlus(5, ChronoUnit.MINUTES);
        claimsSet.getExpirationTime().setTime(expiryDate.getTime());
        var privateKeyJWT =
                new PrivateKeyJWT(claimsSet, JWSAlgorithm.RS256, privateKey, null, null);
        Map<String, List<String>> customParams = new HashMap<>();
        customParams.put(
                "grant_type", Collections.singletonList(GrantType.REFRESH_TOKEN.getValue()));
        customParams.put("client_id", Collections.singletonList(CLIENT_ID));
        customParams.put("refresh_token", Collections.singletonList(refreshToken.getValue()));
        Map<String, List<String>> privateKeyParams = privateKeyJWT.toParameters();
        privateKeyParams.putAll(customParams);
        String requestParams = URLUtils.serializeParameters(privateKeyParams);
        var response = makeRequest(Optional.of(requestParams), Map.of(), Map.of());

        assertThat(response, hasStatus(200));
        JSONObject jsonResponse = JSONObjectUtils.parse(response.getBody());

        assertNotNull(
                TokenResponse.parse(jsonResponse)
                        .toSuccessResponse()
                        .getTokens()
                        .getRefreshToken());
        assertNotNull(
                TokenResponse.parse(jsonResponse)
                        .toSuccessResponse()
                        .getTokens()
                        .getBearerAccessToken());

        AuditAssertionsHelper.assertNoTxmaAuditEventsReceived(txmaAuditQueue);
    }

    @Test
    void shouldCallTokenResourceWithUsedRefreshTokenGrantAndReturn400() throws Exception {
        Scope scope =
                new Scope(
                        OIDCScopeValue.OPENID, OIDCScopeValue.EMAIL, OIDCScopeValue.OFFLINE_ACCESS);
        Subject publicSubject = new Subject();
        KeyPair keyPair = KeyPairUtils.generateRsaKeyPair();
        registerClientWithPrivateKeyJwtAuthentication(
                keyPair.getPublic(), scope, SubjectType.PAIRWISE);
        SignedJWT signedJWT = generateSignedRefreshToken(scope, publicSubject);
        RefreshToken refreshToken = new RefreshToken(signedJWT.serialize());
        orchRefreshTokenExtension.saveRefreshToken(
                signedJWT.getJWTClaimsSet().getJWTID(),
                INTERNAL_PAIRWISE_SUBJECT_ID,
                refreshToken.getValue(),
                AUTH_CODE);

        PrivateKey privateKey = keyPair.getPrivate();
        JWTAuthenticationClaimsSet claimsSet =
                new JWTAuthenticationClaimsSet(
                        new ClientID(CLIENT_ID), new Audience(ROOT_RESOURCE_URL + TOKEN_ENDPOINT));
        var expiryDate = NowHelper.nowPlus(5, ChronoUnit.MINUTES);
        claimsSet.getExpirationTime().setTime(expiryDate.getTime());
        var privateKeyJWT =
                new PrivateKeyJWT(claimsSet, JWSAlgorithm.RS256, privateKey, null, null);
        Map<String, List<String>> customParams = new HashMap<>();
        customParams.put(
                "grant_type", Collections.singletonList(GrantType.REFRESH_TOKEN.getValue()));
        customParams.put("client_id", Collections.singletonList(CLIENT_ID));
        customParams.put("refresh_token", Collections.singletonList(refreshToken.getValue()));
        Map<String, List<String>> privateKeyParams = privateKeyJWT.toParameters();
        privateKeyParams.putAll(customParams);
        String requestParams = URLUtils.serializeParameters(privateKeyParams);
        var response = makeRequest(Optional.of(requestParams), Map.of(), Map.of());

        assertThat(response, hasStatus(200));
        JSONObject jsonResponse = JSONObjectUtils.parse(response.getBody());
        Tokens tokens = TokenResponse.parse(jsonResponse).toSuccessResponse().getTokens();
        assertNotNull(tokens.getRefreshToken());
        assertNotNull(tokens.getBearerAccessToken());

        // try to reuse a previously used token
        var secondResponse = makeRequest(Optional.of(requestParams), Map.of(), Map.of());
        assertThat(secondResponse, hasStatus(400));
        assertThat(
                secondResponse,
                hasBody(
                        new ErrorObject(OAuth2Error.INVALID_GRANT_CODE, "Invalid Refresh token")
                                .toJSONObject()
                                .toJSONString()));

        AuditAssertionsHelper.assertNoTxmaAuditEventsReceived(txmaAuditQueue);
    }

    @Test
    void shouldCallTokenResourceWithRefreshTokenGrantAndReturn400WhenStoredTokenNotMatchingRequest()
            throws Exception {
        Scope scope =
                new Scope(
                        OIDCScopeValue.OPENID, OIDCScopeValue.EMAIL, OIDCScopeValue.OFFLINE_ACCESS);
        Subject publicSubject = new Subject();
        KeyPair keyPair = KeyPairUtils.generateRsaKeyPair();
        registerClientWithPrivateKeyJwtAuthentication(
                keyPair.getPublic(), scope, SubjectType.PAIRWISE);
        SignedJWT signedJWT = generateSignedRefreshToken(scope, publicSubject);
        RefreshToken refreshToken = new RefreshToken(signedJWT.serialize());
        orchRefreshTokenExtension.saveRefreshToken(
                signedJWT.getJWTClaimsSet().getJWTID(),
                INTERNAL_PAIRWISE_SUBJECT_ID,
                "a-different-token-value",
                AUTH_CODE);

        PrivateKey privateKey = keyPair.getPrivate();
        JWTAuthenticationClaimsSet claimsSet =
                new JWTAuthenticationClaimsSet(
                        new ClientID(CLIENT_ID), new Audience(ROOT_RESOURCE_URL + TOKEN_ENDPOINT));
        var expiryDate = NowHelper.nowPlus(5, ChronoUnit.MINUTES);
        claimsSet.getExpirationTime().setTime(expiryDate.getTime());
        var privateKeyJWT =
                new PrivateKeyJWT(claimsSet, JWSAlgorithm.RS256, privateKey, null, null);
        Map<String, List<String>> customParams = new HashMap<>();
        customParams.put(
                "grant_type", Collections.singletonList(GrantType.REFRESH_TOKEN.getValue()));
        customParams.put("client_id", Collections.singletonList(CLIENT_ID));
        customParams.put("refresh_token", Collections.singletonList(refreshToken.getValue()));
        Map<String, List<String>> privateKeyParams = privateKeyJWT.toParameters();
        privateKeyParams.putAll(customParams);
        String requestParams = URLUtils.serializeParameters(privateKeyParams);
        var response = makeRequest(Optional.of(requestParams), Map.of(), Map.of());

        assertThat(response, hasStatus(400));
        assertThat(
                response,
                hasBody(
                        new ErrorObject(OAuth2Error.INVALID_GRANT_CODE, "Invalid Refresh token")
                                .toJSONObject()
                                .toJSONString()));

        AuditAssertionsHelper.assertNoTxmaAuditEventsReceived(txmaAuditQueue);
    }

    @Test
    void
            shouldCallTokenResourceUsingClientSecretPostAndWarnWhenClientIdInAuthCodeDoesNotMatchRequest() {
        var clientSecret = new Secret();
        Scope scope =
                new Scope(
                        OIDCScopeValue.OPENID.getValue(), OIDCScopeValue.OFFLINE_ACCESS.getValue());
        registerClientSecretClient(
                "test-client-1",
                clientSecret.getValue(),
                ClientAuthenticationMethod.CLIENT_SECRET_POST,
                scope);
        registerClientSecretClient(
                "test-client-2",
                clientSecret.getValue(),
                ClientAuthenticationMethod.CLIENT_SECRET_POST,
                scope);

        createAuthCodeForClient(Optional.of("test-client-1"), "test-auth-code-1");
        createAuthCodeForClient(Optional.of("test-client-2"), "test-auth-code-2");

        var baseTokenRequest =
                constructBaseTokenRequest(
                        scope,
                        Optional.of("Cl.Cm"),
                        Optional.empty(),
                        Optional.of("test-client-1"),
                        CODE_VERIFIER.getValue());
        var response =
                makeTokenRequestWithClientSecretPost(
                        "test-client-1", baseTokenRequest, clientSecret);

        assertThat(response, hasStatus(400));
        assertThat(response, hasBody(OAuth2Error.INVALID_GRANT.toJSONObject().toJSONString()));
    }

    @Test
    void shouldCallTokenResourceUsingPrivateKeyJwtAndWarnWhenClientIdInAuthCodeDoesNotMatchRequest()
            throws Exception {
        KeyPair keyPair = KeyPairUtils.generateRsaKeyPair();
        Scope scope =
                new Scope(
                        OIDCScopeValue.OPENID.getValue(), OIDCScopeValue.OFFLINE_ACCESS.getValue());
        registerClientWithPrivateKeyJwtAuthentication(
                "test-client-1", keyPair.getPublic(), scope, SubjectType.PAIRWISE);

        createAuthCodeForClient(Optional.of("test-client-1"), "test-auth-code-1");
        createAuthCodeForClient(Optional.of("test-client-2"), "test-auth-code-2");

        var baseTokenRequest =
                constructBaseTokenRequest(
                        scope,
                        Optional.of("Cl.Cm"),
                        Optional.empty(),
                        Optional.of("test-client-1"),
                        CODE_VERIFIER.getValue());
        var response =
                makeTokenRequestWithPrivateKeyJWT(
                        "test-client-1",
                        baseTokenRequest,
                        keyPair.getPrivate(),
                        new Audience(ROOT_RESOURCE_URL + TOKEN_ENDPOINT).toSingleAudienceList());

        assertThat(response, hasStatus(400));
        assertThat(response, hasBody(OAuth2Error.INVALID_GRANT.toJSONObject().toJSONString()));
    }

    @Test
    void shouldCallTokenResourceAndWarnWhenPkceValidationFails() throws Exception {
        CodeVerifier invalidCodeVerifier = new CodeVerifier();
        KeyPair keyPair = KeyPairUtils.generateRsaKeyPair();
        Scope scope =
                new Scope(
                        OIDCScopeValue.OPENID.getValue(), OIDCScopeValue.OFFLINE_ACCESS.getValue());
        registerClientWithPrivateKeyJwtAuthentication(
                keyPair.getPublic(), scope, SubjectType.PUBLIC);
        var baseTokenRequest =
                constructBaseTokenRequest(
                        scope,
                        Optional.empty(),
                        Optional.empty(),
                        Optional.of(CLIENT_ID),
                        invalidCodeVerifier.getValue());

        var response = makeTokenRequestWithPrivateKeyJWT(baseTokenRequest, keyPair.getPrivate());

        assertThat(response, hasStatus(400));
        assertThat(
                response,
                hasBody(
                        new ErrorObject(
                                        OAuth2Error.INVALID_GRANT_CODE,
                                        "PKCE code verification failed")
                                .toJSONObject()
                                .toJSONString()));
    }

    private SignedJWT generateSignedRefreshToken(Scope scope, Subject publicSubject) {
        Date expiryDate = NowHelper.nowPlus(60, ChronoUnit.MINUTES);
        JWTClaimsSet claimsSet =
                new JWTClaimsSet.Builder()
                        .claim("scope", scope.toStringList())
                        .issuer("issuer-id")
                        .expirationTime(expiryDate)
                        .issueTime(NowHelper.now())
                        .claim("client_id", CLIENT_ID)
                        .subject(publicSubject.getValue())
                        .jwtID(IdGenerator.generate())
                        .build();
        return externalTokenSigner.signJwt(claimsSet);
    }

    private void registerClientWithPrivateKeyJwtAuthentication(
            PublicKey publicKey, Scope scope, SubjectType subjectType) {
        registerClientWithPrivateKeyJwtAuthentication(CLIENT_ID, publicKey, scope, subjectType);
    }

    private void registerClientWithPrivateKeyJwtAuthentication(
            String clientId, PublicKey publicKey, Scope scope, SubjectType subjectType) {
        clientStore
                .createClient()
                .withClientId(clientId)
                .withPublicKey(Base64.getMimeEncoder().encodeToString(publicKey.getEncoded()))
                .withScopes(scope.toStringList())
                .withSubjectType(subjectType.toString())
                .withIdTokenSigningAlgorithm(ES256.getName())
                .withTokenAuthMethod(ClientAuthenticationMethod.PRIVATE_KEY_JWT.getValue())
                .saveToDynamo();
    }

    private void registerClientSecretClient(
            String clientSecret,
            ClientAuthenticationMethod clientAuthenticationMethod,
            Scope scope) {
        registerClientSecretClient(CLIENT_ID, clientSecret, clientAuthenticationMethod, scope);
    }

    private void registerClientSecretClient(
            String clientId,
            String clientSecret,
            ClientAuthenticationMethod clientAuthenticationMethod,
            Scope scope) {
        clientStore
                .createClient()
                .withClientId(clientId)
                .withScopes(scope.toStringList())
                .withSubjectType("pairwise")
                .withClientSecret(clientSecret)
                .withIdTokenSigningAlgorithm(ES256.getName())
                .withTokenAuthMethod(clientAuthenticationMethod.getValue())
                .saveToDynamo();
    }

    private AuthenticationRequest generateAuthRequest(
            Scope scope, Optional<String> vtr, Optional<OIDCClaimsRequest> claimsRequest) {
        ResponseType responseType = new ResponseType(ResponseType.Value.CODE);
        State state = new State();
        Nonce nonce = new Nonce();
        AuthenticationRequest.Builder builder =
                new AuthenticationRequest.Builder(
                                responseType,
                                scope,
                                new ClientID(CLIENT_ID),
                                URI.create("http://localhost/redirect"))
                        .state(state)
                        .nonce(nonce)
                        .customParameter("code_challenge", CODE_CHALLENGE_STRING);
        claimsRequest.ifPresent(builder::claims);
        vtr.ifPresent(v -> builder.customParameter("vtr", v));

        return builder.build();
    }

    private APIGatewayProxyResponseEvent makeTokenRequestWithPrivateKeyJWT(
            Map<String, List<String>> requestParams, PrivateKey privateKey) throws JOSEException {
        return makeTokenRequestWithPrivateKeyJWT(
                CLIENT_ID,
                requestParams,
                privateKey,
                Collections.singletonList(new Audience(ROOT_RESOURCE_URL + TOKEN_ENDPOINT)));
    }

    private APIGatewayProxyResponseEvent makeTokenRequestWithPrivateKeyJWT(
            String clientId,
            Map<String, List<String>> requestParams,
            PrivateKey privateKey,
            List<Audience> audience)
            throws JOSEException {
        var expiryDate = NowHelper.nowPlus(5, ChronoUnit.MINUTES);
        var claimsSet =
                new JWTAuthenticationClaimsSet(
                        new ClientID(clientId), audience, expiryDate, null, null, new JWTID());
        claimsSet.getExpirationTime().setTime(expiryDate.getTime());
        var privateKeyJWT =
                new PrivateKeyJWT(claimsSet, JWSAlgorithm.RS256, privateKey, null, null);
        requestParams.putAll(privateKeyJWT.toParameters());

        var requestBody = URLUtils.serializeParameters(requestParams);
        return makeRequest(Optional.of(requestBody), Map.of(), Map.of());
    }

    private APIGatewayProxyResponseEvent makeTokenRequestWithClientSecretPost(
            Map<String, List<String>> requestParams, Secret clientSecret) {
        return makeTokenRequestWithClientSecretPost(CLIENT_ID, requestParams, clientSecret);
    }

    private APIGatewayProxyResponseEvent makeTokenRequestWithClientSecretPost(
            String clientId, Map<String, List<String>> requestParams, Secret clientSecret) {
        var clientSecretPost = new ClientSecretPost(new ClientID(clientId), clientSecret);
        clientSecretPost.toParameters();
        requestParams.putAll(clientSecretPost.toParameters());
        var requestBody = URLUtils.serializeParameters(requestParams);
        return makeRequest(Optional.of(requestBody), Map.of(), Map.of());
    }

    private Map<String, List<String>> constructBaseTokenRequest(
            Scope scope,
            Optional<String> vtr,
            Optional<OIDCClaimsRequest> oidcClaimsRequest,
            Optional<String> clientId) {
        return constructBaseTokenRequest(
                scope, vtr, oidcClaimsRequest, clientId, CODE_VERIFIER.getValue());
    }

    private Map<String, List<String>> constructBaseTokenRequest(
            Scope scope,
            Optional<String> vtr,
            Optional<OIDCClaimsRequest> oidcClaimsRequest,
            Optional<String> clientId,
            String codeVerifier) {
        List<VectorOfTrust> vtrList = List.of(VectorOfTrust.getDefaults());
        if (vtr.isPresent()) {
            vtrList =
                    VectorOfTrust.parseFromAuthRequestAttribute(
                            singletonList(JsonArrayHelper.jsonArrayOf(vtr.get())));
        }
        var creationDate = LocalDateTime.now();
        var authRequestParams = generateAuthRequest(scope, vtr, oidcClaimsRequest).toParameters();
        orchClientSessionExtension.storeClientSession(
                new OrchClientSessionItem(
                                CLIENT_SESSION_ID,
                                authRequestParams,
                                creationDate,
                                vtrList,
                                "client-name")
                        .withRpPairwiseId(RP_PAIRWISE_ID)
                        .withPublicSubjectId(PUBLIC_SUBJECT_ID));

        AuthorizationCode code =
                orchAuthCodeExtension.generateAndSaveAuthorisationCode(
                        CLIENT_ID,
                        CLIENT_SESSION_ID,
                        TEST_EMAIL,
                        AUTH_TIME,
                        INTERNAL_PAIRWISE_SUBJECT_ID);

        Map<String, List<String>> customParams = new HashMap<>();
        customParams.put(
                "grant_type", Collections.singletonList(GrantType.AUTHORIZATION_CODE.getValue()));
        clientId.map(cid -> customParams.put("client_id", Collections.singletonList(cid)));
        customParams.put("code", Collections.singletonList(code.getValue()));
        customParams.put("redirect_uri", Collections.singletonList(REDIRECT_URI));
        customParams.put("code_verifier", Collections.singletonList(codeVerifier));
        return customParams;
    }

    private Map<String, List<String>> createAuthCodeForClient(
            Optional<String> clientId, String code) {
        Map<String, List<String>> customParams = new HashMap<>();
        customParams.put(
                "grant_type", Collections.singletonList(GrantType.AUTHORIZATION_CODE.getValue()));
        clientId.map(cid -> customParams.put("client_id", Collections.singletonList(cid)));
        customParams.put("code", Collections.singletonList(code));
        customParams.put("redirect_uri", Collections.singletonList(REDIRECT_URI));
        return customParams;
    }

    private String createCodeChallengeFromCodeVerifier(CodeVerifier codeVerifier) {
        return CodeChallenge.compute(CodeChallengeMethod.S256, codeVerifier).toString();
    }
}
