package uk.gov.di.authentication.oidc.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.auth.PrivateKeyJWT;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.pkce.CodeChallenge;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.oauth2.sdk.util.URLUtils;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCClaimsRequest;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSetRequest;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import net.minidev.json.JSONArray;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import uk.gov.di.orchestration.shared.entity.AuthCodeExchangeData;
import uk.gov.di.orchestration.shared.entity.ClientRegistry;
import uk.gov.di.orchestration.shared.entity.OrchClientSessionItem;
import uk.gov.di.orchestration.shared.entity.RefreshTokenStore;
import uk.gov.di.orchestration.shared.entity.UserProfile;
import uk.gov.di.orchestration.shared.entity.VectorOfTrust;
import uk.gov.di.orchestration.shared.exceptions.TokenAuthInvalidException;
import uk.gov.di.orchestration.shared.helpers.ClientSubjectHelper;
import uk.gov.di.orchestration.shared.helpers.NowHelper;
import uk.gov.di.orchestration.shared.serialization.Json;
import uk.gov.di.orchestration.shared.services.CloudwatchMetricsService;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.DynamoService;
import uk.gov.di.orchestration.shared.services.OrchAuthCodeService;
import uk.gov.di.orchestration.shared.services.OrchClientSessionService;
import uk.gov.di.orchestration.shared.services.RedisConnectionService;
import uk.gov.di.orchestration.shared.services.SerializationService;
import uk.gov.di.orchestration.shared.services.TokenService;
import uk.gov.di.orchestration.shared.services.TokenValidationService;
import uk.gov.di.orchestration.shared.validation.TokenClientAuthValidator;
import uk.gov.di.orchestration.shared.validation.TokenClientAuthValidatorFactory;
import uk.gov.di.orchestration.sharedtest.helper.JsonArrayHelper;
import uk.gov.di.orchestration.sharedtest.helper.TokenGeneratorHelper;
import uk.gov.di.orchestration.sharedtest.utils.KeyPairUtils;

import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.text.ParseException;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.oidc.helper.RequestObjectTestHelper.generateSignedJWT;
import static uk.gov.di.orchestration.shared.domain.CloudwatchMetricDimensions.CLIENT;
import static uk.gov.di.orchestration.shared.domain.CloudwatchMetricDimensions.ENVIRONMENT;
import static uk.gov.di.orchestration.shared.domain.CloudwatchMetrics.SUCCESSFUL_TOKEN_ISSUED;
import static uk.gov.di.orchestration.shared.entity.CustomScopeValue.DOC_CHECKING_APP;
import static uk.gov.di.orchestration.sharedtest.helper.TokenGeneratorHelper.generateIDToken;
import static uk.gov.di.orchestration.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasBody;
import static uk.gov.di.orchestration.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

public class TokenHandlerTest {

    private static final String TEST_EMAIL = "joe.bloggs@digital.cabinet-office.gov.uk";
    private static final String PHONE_NUMBER = "01234567890";
    private static final String REDIRECT_URI = "http://localhost/redirect";
    private static final ByteBuffer SALT =
            ByteBuffer.wrap("a-test-salt".getBytes(StandardCharsets.UTF_8));
    private static final String RP_SECTOR_URI = "https://test.com";
    private static final String RP_SECTOR_HOST = "test.com";

    private static final String INTERNAL_SECTOR_URI = "https://test.account.gov.uk";
    private static final String INTERNAL_SECTOR_HOST = "test.account.gov.uk";
    private static final Subject INTERNAL_SUBJECT = new Subject();
    private static final Subject RP_PAIRWISE_SUBJECT =
            new Subject(
                    ClientSubjectHelper.calculatePairwiseIdentifier(
                            INTERNAL_SUBJECT.getValue(), RP_SECTOR_HOST, SALT.array()));
    private static final Subject INTERNAL_PAIRWISE_SUBJECT =
            new Subject(
                    ClientSubjectHelper.calculatePairwiseIdentifier(
                            INTERNAL_SUBJECT.getValue(), INTERNAL_SECTOR_HOST, SALT.array()));
    private static final Subject DOC_APP_USER_PUBLIC_SUBJECT = new Subject();
    private static final String AUDIENCE = "oidc-audience";
    private static final State STATE = new State();
    private static final String CLIENT_ID = "test-id";
    private static final String CLIENT_NAME = "test-client-name";
    private static final String IGNORE_CLIENT_ID = "ignore-test-id";
    private static final ClientID DOC_APP_CLIENT_ID = new ClientID("doc-app-test-id");
    private static final Scope SCOPES =
            new Scope(OIDCScopeValue.OPENID, OIDCScopeValue.EMAIL, OIDCScopeValue.OFFLINE_ACCESS);
    private static final String BASE_URI = "http://localhost";
    private static final String TOKEN_URI = "http://localhost/token";
    public static final String CLIENT_SESSION_ID = "a-client-session-id";
    private static final Nonce NONCE = new Nonce();
    private static final String REFRESH_TOKEN_PREFIX = "REFRESH_TOKEN:";
    private static final Long AUTH_TIME = NowHelper.now().toInstant().getEpochSecond() - 120L;
    private final BearerAccessToken accessToken = new BearerAccessToken();
    private final RefreshToken refreshToken = new RefreshToken();
    private final Context context = mock(Context.class);
    private final DynamoService dynamoService = mock(DynamoService.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final TokenService tokenService = mock(TokenService.class);
    private final TokenValidationService tokenValidationService =
            mock(TokenValidationService.class);
    private final TokenClientAuthValidatorFactory tokenClientAuthValidatorFactory =
            mock(TokenClientAuthValidatorFactory.class);
    private final TokenClientAuthValidator tokenClientAuthValidator =
            mock(TokenClientAuthValidator.class);
    private final OrchAuthCodeService orchAuthCodeService = mock(OrchAuthCodeService.class);
    private final OrchClientSessionService orchClientSessionService =
            mock(OrchClientSessionService.class);
    private final RedisConnectionService redisConnectionService =
            mock(RedisConnectionService.class);
    private final CloudwatchMetricsService cloudwatchMetricsService =
            mock(CloudwatchMetricsService.class);
    private TokenHandler handler;
    private final Json objectMapper = SerializationService.getInstance();
    private final LocalDateTime clientSessionCreationTime = LocalDateTime.now();

    @BeforeEach
    void setUp() {
        when(configurationService.getInternalSectorURI()).thenReturn(INTERNAL_SECTOR_URI);
        when(configurationService.getSessionExpiry()).thenReturn(1234L);
        when(configurationService.getEnvironment()).thenReturn("test");
        when(configurationService.isPkceEnabled()).thenReturn(false);
        when(dynamoService.getOrGenerateSalt(any())).thenCallRealMethod();
        handler =
                new TokenHandler(
                        tokenService,
                        dynamoService,
                        configurationService,
                        orchAuthCodeService,
                        orchClientSessionService,
                        tokenValidationService,
                        redisConnectionService,
                        tokenClientAuthValidatorFactory,
                        cloudwatchMetricsService);
    }

    private static Stream<Arguments> validVectorValues() {
        return Stream.of(
                Arguments.of("Cl.Cm", true),
                Arguments.of("Cl", true),
                Arguments.of("P2.Cl.Cm", true),
                Arguments.of("Cl.Cm", false),
                Arguments.of("Cl", false),
                Arguments.of("P2.Cl.Cm", false));
    }

    @ParameterizedTest
    @MethodSource("validVectorValues")
    void shouldReturn200ForSuccessfulTokenRequest(String vectorValue, boolean clientIdInHeader)
            throws JOSEException, TokenAuthInvalidException {
        KeyPair keyPair = generateRsaKeyPair();
        UserProfile userProfile = generateUserProfile();
        SignedJWT signedJWT =
                generateIDToken(
                        CLIENT_ID,
                        RP_PAIRWISE_SUBJECT,
                        "issuer-url",
                        new ECKeyGenerator(Curve.P_256).algorithm(JWSAlgorithm.ES256).generate());
        OIDCTokenResponse tokenResponse =
                new OIDCTokenResponse(new OIDCTokens(signedJWT, accessToken, refreshToken));
        PrivateKeyJWT privateKeyJWT = generatePrivateKeyJWT(keyPair.getPrivate());
        ClientRegistry clientRegistry = generateClientRegistry(keyPair, CLIENT_ID);

        when(tokenService.validateTokenRequestParams(anyString())).thenReturn(Optional.empty());
        when(tokenClientAuthValidatorFactory.getTokenAuthenticationValidator(any()))
                .thenReturn(Optional.of(tokenClientAuthValidator));
        when(tokenClientAuthValidator.validateTokenAuthAndReturnClientRegistryIfValid(
                        anyString(), any()))
                .thenReturn(clientRegistry);
        String authCode = new AuthorizationCode().toString();
        AuthenticationRequest authenticationRequest =
                generateAuthRequest(JsonArrayHelper.jsonArrayOf(vectorValue));
        List<VectorOfTrust> vtr =
                VectorOfTrust.parseFromAuthRequestAttribute(
                        authenticationRequest.getCustomParameter("vtr"));
        VectorOfTrust lowestLevelVtr = VectorOfTrust.orderVtrList(vtr).get(0);
        setupClientSessions(authCode, authenticationRequest.toParameters(), vtr);
        when(dynamoService.getUserProfileByEmail(eq(TEST_EMAIL))).thenReturn(userProfile);
        when(tokenService.generateTokenResponse(
                        CLIENT_ID,
                        INTERNAL_SUBJECT,
                        SCOPES,
                        Map.of("nonce", NONCE),
                        RP_PAIRWISE_SUBJECT,
                        INTERNAL_PAIRWISE_SUBJECT,
                        null,
                        false,
                        JWSAlgorithm.ES256,
                        CLIENT_SESSION_ID,
                        lowestLevelVtr.retrieveVectorOfTrustForToken(),
                        AUTH_TIME))
                .thenReturn(tokenResponse);

        APIGatewayProxyResponseEvent result =
                generateApiGatewayRequest(privateKeyJWT, authCode, CLIENT_ID, clientIdInHeader);
        assertThat(result, hasStatus(200));
        assertTrue(result.getBody().contains(refreshToken.getValue()));
        assertTrue(result.getBody().contains(accessToken.getValue()));
        verify(cloudwatchMetricsService)
                .incrementCounter(
                        SUCCESSFUL_TOKEN_ISSUED.getValue(),
                        Map.of(
                                ENVIRONMENT.getValue(),
                                configurationService.getEnvironment(),
                                CLIENT.getValue(),
                                CLIENT_ID));
        var orchClientSessionCaptor = ArgumentCaptor.forClass(OrchClientSessionItem.class);
        verify(orchClientSessionService)
                .updateStoredClientSession(orchClientSessionCaptor.capture());
        assertEquals(signedJWT.serialize(), orchClientSessionCaptor.getValue().getIdTokenHint());

        assertAuthCodeExchangeDataRetrieved(authCode);
    }

    @Test
    void shouldReturn400ForTokenRequestIfClientIdInAuthCodeIsDifferentFromRequestParams()
            throws JOSEException, TokenAuthInvalidException {
        KeyPair keyPair = generateRsaKeyPair();
        UserProfile userProfile = generateUserProfile();
        SignedJWT signedJWT =
                generateIDToken(
                        CLIENT_ID,
                        RP_PAIRWISE_SUBJECT,
                        "issuer-url",
                        new ECKeyGenerator(Curve.P_256).algorithm(JWSAlgorithm.ES256).generate());
        OIDCTokenResponse tokenResponse =
                new OIDCTokenResponse(new OIDCTokens(signedJWT, accessToken, refreshToken));
        PrivateKeyJWT privateKeyJWT = generatePrivateKeyJWT(keyPair.getPrivate());
        ClientRegistry clientRegistry = generateClientRegistry(keyPair, CLIENT_ID);

        when(tokenService.validateTokenRequestParams(anyString())).thenReturn(Optional.empty());
        when(tokenClientAuthValidatorFactory.getTokenAuthenticationValidator(any()))
                .thenReturn(Optional.of(tokenClientAuthValidator));
        when(tokenClientAuthValidator.validateTokenAuthAndReturnClientRegistryIfValid(
                        anyString(), any()))
                .thenReturn(clientRegistry);
        String authCode = new AuthorizationCode().toString();
        AuthenticationRequest authenticationRequest =
                generateAuthRequest(JsonArrayHelper.jsonArrayOf("Cl.Cm"));
        List<VectorOfTrust> vtr =
                VectorOfTrust.parseFromAuthRequestAttribute(
                        authenticationRequest.getCustomParameter("vtr"));
        VectorOfTrust lowestLevelVtr = VectorOfTrust.orderVtrList(vtr).get(0);
        setupClientSessions(
                authCode, authenticationRequest.toParameters(), vtr, "a-different-client-id", null);
        when(dynamoService.getUserProfileByEmail(eq(TEST_EMAIL))).thenReturn(userProfile);
        when(tokenService.generateTokenResponse(
                        CLIENT_ID,
                        INTERNAL_SUBJECT,
                        SCOPES,
                        Map.of("nonce", NONCE),
                        RP_PAIRWISE_SUBJECT,
                        INTERNAL_PAIRWISE_SUBJECT,
                        null,
                        false,
                        JWSAlgorithm.ES256,
                        CLIENT_SESSION_ID,
                        lowestLevelVtr.retrieveVectorOfTrustForToken(),
                        AUTH_TIME))
                .thenReturn(tokenResponse);

        APIGatewayProxyResponseEvent result =
                generateApiGatewayRequest(privateKeyJWT, authCode, CLIENT_ID, true);
        assertThat(result, hasStatus(400));
        assertThat(result, hasBody(OAuth2Error.INVALID_GRANT.toJSONObject().toJSONString()));
        verify(cloudwatchMetricsService, never())
                .incrementCounter(eq(SUCCESSFUL_TOKEN_ISSUED.getValue()), anyMap());

        assertAuthCodeExchangeDataRetrieved(authCode);
    }

    @ParameterizedTest
    @MethodSource("validVectorValues")
    void shouldReturn200ForSuccessfulTokenRequestWithRsaSigning(
            String vectorValue, boolean clientIdInHeader)
            throws JOSEException, TokenAuthInvalidException {
        when(configurationService.isRsaSigningAvailable()).thenReturn(true);

        KeyPair keyPair = generateRsaKeyPair();
        UserProfile userProfile = generateUserProfile();
        SignedJWT signedJWT =
                generateIDToken(
                        CLIENT_ID,
                        RP_PAIRWISE_SUBJECT,
                        "issuer-url",
                        new RSAKeyGenerator(2048).algorithm(JWSAlgorithm.RS256).generate());
        OIDCTokenResponse tokenResponse =
                new OIDCTokenResponse(new OIDCTokens(signedJWT, accessToken, refreshToken));
        PrivateKeyJWT privateKeyJWT = generatePrivateKeyJWT(keyPair.getPrivate());
        ClientRegistry clientRegistry =
                generateClientRegistry(keyPair, CLIENT_ID)
                        .withIdTokenSigningAlgorithm(JWSAlgorithm.RS256.getName());

        when(tokenService.validateTokenRequestParams(anyString())).thenReturn(Optional.empty());
        when(tokenClientAuthValidatorFactory.getTokenAuthenticationValidator(any()))
                .thenReturn(Optional.of(tokenClientAuthValidator));
        when(tokenClientAuthValidator.validateTokenAuthAndReturnClientRegistryIfValid(
                        anyString(), any()))
                .thenReturn(clientRegistry);
        String authCode = new AuthorizationCode().toString();
        AuthenticationRequest authenticationRequest =
                generateAuthRequest(JsonArrayHelper.jsonArrayOf(vectorValue));
        List<VectorOfTrust> vtr =
                VectorOfTrust.parseFromAuthRequestAttribute(
                        authenticationRequest.getCustomParameter("vtr"));
        VectorOfTrust lowestLevelVtr = VectorOfTrust.orderVtrList(vtr).get(0);
        setupClientSessions(authCode, authenticationRequest.toParameters(), vtr);
        when(dynamoService.getUserProfileByEmail(eq(TEST_EMAIL))).thenReturn(userProfile);
        when(tokenService.generateTokenResponse(
                        CLIENT_ID,
                        INTERNAL_SUBJECT,
                        SCOPES,
                        Map.of("nonce", NONCE),
                        RP_PAIRWISE_SUBJECT,
                        INTERNAL_PAIRWISE_SUBJECT,
                        null,
                        false,
                        JWSAlgorithm.RS256,
                        CLIENT_SESSION_ID,
                        lowestLevelVtr.retrieveVectorOfTrustForToken(),
                        AUTH_TIME))
                .thenReturn(tokenResponse);

        APIGatewayProxyResponseEvent result =
                generateApiGatewayRequest(privateKeyJWT, authCode, CLIENT_ID, clientIdInHeader);
        assertThat(result, hasStatus(200));
        assertTrue(result.getBody().contains(refreshToken.getValue()));
        assertTrue(result.getBody().contains(accessToken.getValue()));
        verify(cloudwatchMetricsService)
                .incrementCounter(
                        SUCCESSFUL_TOKEN_ISSUED.getValue(),
                        Map.of(
                                ENVIRONMENT.getValue(),
                                configurationService.getEnvironment(),
                                CLIENT.getValue(),
                                CLIENT_ID));

        assertAuthCodeExchangeDataRetrieved(authCode);
    }

    @ParameterizedTest
    @NullSource
    @ValueSource(strings = {CLIENT_ID})
    void shouldReturn200ForSuccessfulRefreshTokenRequest(String clientId)
            throws JOSEException, ParseException, Json.JsonException, TokenAuthInvalidException {
        SignedJWT signedRefreshToken = createSignedRefreshToken();
        KeyPair keyPair = generateRsaKeyPair();
        RefreshToken refreshToken = new RefreshToken(signedRefreshToken.serialize());
        OIDCTokenResponse tokenResponse =
                new OIDCTokenResponse(
                        new OIDCTokens("test-id-token-string", accessToken, refreshToken));
        PrivateKeyJWT privateKeyJWT = generatePrivateKeyJWT(keyPair.getPrivate());
        ClientRegistry clientRegistry = generateClientRegistry(keyPair, CLIENT_ID);

        when(tokenService.validateTokenRequestParams(anyString())).thenReturn(Optional.empty());
        when(tokenClientAuthValidatorFactory.getTokenAuthenticationValidator(any()))
                .thenReturn(Optional.of(tokenClientAuthValidator));
        when(tokenClientAuthValidator.validateTokenAuthAndReturnClientRegistryIfValid(
                        anyString(), any()))
                .thenReturn(clientRegistry);

        when(tokenValidationService.validateRefreshTokenSignatureAndExpiry(refreshToken))
                .thenReturn(true);
        when(tokenValidationService.validateRefreshTokenScopes(
                        SCOPES.toStringList(), SCOPES.toStringList()))
                .thenReturn(true);
        RefreshTokenStore tokenStore =
                new RefreshTokenStore(
                        refreshToken.getValue(),
                        INTERNAL_SUBJECT.getValue(),
                        INTERNAL_PAIRWISE_SUBJECT.getValue());
        String tokenStoreString = objectMapper.writeValueAsString(tokenStore);
        when(redisConnectionService.popValue(
                        REFRESH_TOKEN_PREFIX + CLIENT_ID + "." + RP_PAIRWISE_SUBJECT.getValue()))
                .thenReturn(null);
        String redisKey = REFRESH_TOKEN_PREFIX + signedRefreshToken.getJWTClaimsSet().getJWTID();
        when(redisConnectionService.popValue(redisKey)).thenReturn(tokenStoreString);
        when(tokenService.generateRefreshTokenResponse(
                        eq(CLIENT_ID),
                        eq(INTERNAL_SUBJECT),
                        eq(SCOPES.toStringList()),
                        eq(RP_PAIRWISE_SUBJECT),
                        eq(INTERNAL_PAIRWISE_SUBJECT),
                        eq(JWSAlgorithm.ES256)))
                .thenReturn(tokenResponse);

        APIGatewayProxyResponseEvent result =
                generateApiGatewayRefreshRequest(privateKeyJWT, refreshToken.getValue(), clientId);
        assertThat(result, hasStatus(200));
        assertTrue(result.getBody().contains(refreshToken.getValue()));
        assertTrue(result.getBody().contains(accessToken.getValue()));
        verify(cloudwatchMetricsService, never())
                .incrementCounter(
                        SUCCESSFUL_TOKEN_ISSUED.getValue(),
                        Map.of(
                                ENVIRONMENT.getValue(),
                                configurationService.getEnvironment(),
                                CLIENT.getValue(),
                                CLIENT_ID));
    }

    @ParameterizedTest
    @NullSource
    @ValueSource(strings = {CLIENT_ID})
    void shouldReturn200ForSuccessfulRefreshTokenRequestWithRsaSigning(String clientId)
            throws JOSEException, ParseException, Json.JsonException, TokenAuthInvalidException {
        when(configurationService.isRsaSigningAvailable()).thenReturn(true);

        SignedJWT signedRefreshToken = createSignedRsaRefreshToken();
        KeyPair keyPair = generateRsaKeyPair();
        RefreshToken refreshToken = new RefreshToken(signedRefreshToken.serialize());
        OIDCTokenResponse tokenResponse =
                new OIDCTokenResponse(new OIDCTokens(accessToken, refreshToken));
        PrivateKeyJWT privateKeyJWT = generatePrivateKeyJWT(keyPair.getPrivate());
        ClientRegistry clientRegistry =
                generateClientRegistry(keyPair, CLIENT_ID).withIdTokenSigningAlgorithm("RSA256");

        when(tokenService.validateTokenRequestParams(anyString())).thenReturn(Optional.empty());
        when(tokenClientAuthValidatorFactory.getTokenAuthenticationValidator(any()))
                .thenReturn(Optional.of(tokenClientAuthValidator));
        when(tokenClientAuthValidator.validateTokenAuthAndReturnClientRegistryIfValid(
                        anyString(), any()))
                .thenReturn(clientRegistry);

        when(tokenValidationService.validateRefreshTokenSignatureAndExpiry(refreshToken))
                .thenReturn(true);
        when(tokenValidationService.validateRefreshTokenScopes(
                        SCOPES.toStringList(), SCOPES.toStringList()))
                .thenReturn(true);
        RefreshTokenStore tokenStore =
                new RefreshTokenStore(
                        refreshToken.getValue(),
                        INTERNAL_SUBJECT.getValue(),
                        INTERNAL_PAIRWISE_SUBJECT.getValue());
        String tokenStoreString = objectMapper.writeValueAsString(tokenStore);
        when(redisConnectionService.popValue(
                        REFRESH_TOKEN_PREFIX + CLIENT_ID + "." + RP_PAIRWISE_SUBJECT.getValue()))
                .thenReturn(null);
        String redisKey = REFRESH_TOKEN_PREFIX + signedRefreshToken.getJWTClaimsSet().getJWTID();
        when(redisConnectionService.popValue(redisKey)).thenReturn(tokenStoreString);
        when(tokenService.generateRefreshTokenResponse(
                        eq(CLIENT_ID),
                        eq(INTERNAL_SUBJECT),
                        eq(SCOPES.toStringList()),
                        eq(RP_PAIRWISE_SUBJECT),
                        eq(INTERNAL_PAIRWISE_SUBJECT),
                        eq(JWSAlgorithm.RS256)))
                .thenReturn(tokenResponse);

        APIGatewayProxyResponseEvent result =
                generateApiGatewayRefreshRequest(privateKeyJWT, refreshToken.getValue(), clientId);
        assertThat(result, hasStatus(200));
        assertTrue(result.getBody().contains(refreshToken.getValue()));
        assertTrue(result.getBody().contains(accessToken.getValue()));
        verify(cloudwatchMetricsService, never())
                .incrementCounter(
                        SUCCESSFUL_TOKEN_ISSUED.getValue(),
                        Map.of(
                                ENVIRONMENT.getValue(),
                                configurationService.getEnvironment(),
                                CLIENT.getValue(),
                                CLIENT_ID));
    }

    @Test
    void shouldReturn400IfClientIsNotValid() throws JOSEException, TokenAuthInvalidException {
        when(tokenService.validateTokenRequestParams(anyString())).thenReturn(Optional.empty());
        KeyPair keyPair = generateRsaKeyPair();
        PrivateKeyJWT privateKeyJWT = generatePrivateKeyJWT(keyPair.getPrivate());
        when(tokenClientAuthValidatorFactory.getTokenAuthenticationValidator(any()))
                .thenReturn(Optional.of(tokenClientAuthValidator));
        when(tokenClientAuthValidator.validateTokenAuthAndReturnClientRegistryIfValid(
                        anyString(), any()))
                .thenThrow(
                        new TokenAuthInvalidException(
                                OAuth2Error.INVALID_CLIENT,
                                ClientAuthenticationMethod.PRIVATE_KEY_JWT,
                                "unknown"));

        APIGatewayProxyResponseEvent result =
                generateApiGatewayRequest(
                        privateKeyJWT, new AuthorizationCode().toString(), CLIENT_ID, true);

        assertEquals(400, result.getStatusCode());
        assertThat(result, hasBody(OAuth2Error.INVALID_CLIENT.toJSONObject().toJSONString()));
        verify(cloudwatchMetricsService, never())
                .incrementCounter(
                        SUCCESSFUL_TOKEN_ISSUED.getValue(),
                        Map.of(
                                ENVIRONMENT.getValue(),
                                configurationService.getEnvironment(),
                                CLIENT.getValue(),
                                CLIENT_ID));
    }

    @Test
    void shouldReturn400IfClientSessionIsNotValid()
            throws JOSEException, TokenAuthInvalidException {
        KeyPair keyPair = generateRsaKeyPair();
        UserProfile userProfile = generateUserProfile();
        SignedJWT signedJWT =
                generateIDToken(
                        CLIENT_ID,
                        RP_PAIRWISE_SUBJECT,
                        "issuer-url",
                        new ECKeyGenerator(Curve.P_256).algorithm(JWSAlgorithm.ES256).generate());
        OIDCTokenResponse tokenResponse =
                new OIDCTokenResponse(new OIDCTokens(signedJWT, accessToken, refreshToken));
        PrivateKeyJWT privateKeyJWT = generatePrivateKeyJWT(keyPair.getPrivate());
        ClientRegistry clientRegistry = generateClientRegistry(keyPair, CLIENT_ID);

        when(tokenService.validateTokenRequestParams(anyString())).thenReturn(Optional.empty());
        when(tokenClientAuthValidatorFactory.getTokenAuthenticationValidator(any()))
                .thenReturn(Optional.of(tokenClientAuthValidator));
        when(tokenClientAuthValidator.validateTokenAuthAndReturnClientRegistryIfValid(
                        anyString(), any()))
                .thenReturn(clientRegistry);
        AuthenticationRequest authenticationRequest = generateAuthRequest();
        List<VectorOfTrust> vtr =
                VectorOfTrust.parseFromAuthRequestAttribute(
                        authenticationRequest.getCustomParameter("vtr"));
        VectorOfTrust lowestLevelVtr = VectorOfTrust.orderVtrList(vtr).get(0);
        when(dynamoService.getUserProfileByEmail(eq(TEST_EMAIL))).thenReturn(userProfile);
        when(tokenService.generateTokenResponse(
                        CLIENT_ID,
                        INTERNAL_SUBJECT,
                        SCOPES,
                        Map.of("nonce", NONCE),
                        RP_PAIRWISE_SUBJECT,
                        INTERNAL_PAIRWISE_SUBJECT,
                        null,
                        false,
                        JWSAlgorithm.ES256,
                        CLIENT_SESSION_ID,
                        lowestLevelVtr.retrieveVectorOfTrustForToken(),
                        AUTH_TIME))
                .thenReturn(tokenResponse);
        setupNoClientSessions();

        String authCode = new AuthorizationCode().getValue();

        APIGatewayProxyResponseEvent result =
                generateApiGatewayRequest(privateKeyJWT, authCode, CLIENT_ID, true);

        assertEquals(400, result.getStatusCode());
        assertThat(result, hasBody(OAuth2Error.INVALID_GRANT.toJSONObject().toJSONString()));

        assertAuthCodeExchangeDataRetrieved(authCode);
    }

    @Test
    void shouldReturn400IfClientIdIsNotValid() {
        ErrorObject error =
                new ErrorObject(
                        OAuth2Error.INVALID_REQUEST_CODE, "Request is missing client_id parameter");
        when(tokenService.validateTokenRequestParams(anyString())).thenReturn(Optional.of(error));
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody("code=343242");

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertEquals(400, result.getStatusCode());
        assertThat(result, hasBody(error.toJSONObject().toJSONString()));
    }

    @Test
    void shouldReturn400IfSignatureOfPrivateKeyJWTCantBeVerified()
            throws JOSEException, TokenAuthInvalidException {
        var privateKeyJWT = generatePrivateKeyJWT(generateRsaKeyPair().getPrivate());

        when(tokenService.validateTokenRequestParams(anyString())).thenReturn(Optional.empty());
        when(tokenClientAuthValidatorFactory.getTokenAuthenticationValidator(any()))
                .thenReturn(Optional.of(tokenClientAuthValidator));
        when(tokenClientAuthValidator.validateTokenAuthAndReturnClientRegistryIfValid(
                        anyString(), any()))
                .thenThrow(
                        new TokenAuthInvalidException(
                                new ErrorObject(
                                        OAuth2Error.INVALID_CLIENT_CODE,
                                        "Invalid signature in private_key_jwt"),
                                ClientAuthenticationMethod.PRIVATE_KEY_JWT,
                                "unknown"));

        var result =
                generateApiGatewayRequest(
                        privateKeyJWT, new AuthorizationCode().toString(), CLIENT_ID, true);

        assertThat(result, hasStatus(400));
        assertThat(
                result,
                hasBody(
                        new ErrorObject(
                                        OAuth2Error.INVALID_CLIENT_CODE,
                                        "Invalid signature in private_key_jwt")
                                .toJSONObject()
                                .toJSONString()));
        verify(cloudwatchMetricsService, never())
                .incrementCounter(
                        SUCCESSFUL_TOKEN_ISSUED.getValue(),
                        Map.of(
                                ENVIRONMENT.getValue(),
                                configurationService.getEnvironment(),
                                CLIENT.getValue(),
                                CLIENT_ID));
    }

    @Test
    void shouldReturn400IfAuthCodeIsNotFound() throws JOSEException, TokenAuthInvalidException {
        KeyPair keyPair = generateRsaKeyPair();
        PrivateKeyJWT privateKeyJWT = generatePrivateKeyJWT(keyPair.getPrivate());
        ClientRegistry clientRegistry = generateClientRegistry(keyPair, CLIENT_ID);

        when(tokenClientAuthValidatorFactory.getTokenAuthenticationValidator(any()))
                .thenReturn(Optional.of(tokenClientAuthValidator));
        when(tokenService.validateTokenRequestParams(anyString())).thenReturn(Optional.empty());
        when(tokenClientAuthValidator.validateTokenAuthAndReturnClientRegistryIfValid(
                        anyString(), any()))
                .thenReturn(clientRegistry);
        String authCode = new AuthorizationCode().toString();
        when(orchAuthCodeService.getExchangeDataForCode(authCode)).thenReturn(Optional.empty());

        APIGatewayProxyResponseEvent result =
                generateApiGatewayRequest(privateKeyJWT, authCode, CLIENT_ID, true);
        assertThat(result, hasStatus(400));
        assertThat(result, hasBody(OAuth2Error.INVALID_GRANT.toJSONObject().toJSONString()));
        verify(cloudwatchMetricsService, never())
                .incrementCounter(
                        SUCCESSFUL_TOKEN_ISSUED.getValue(),
                        Map.of(
                                ENVIRONMENT.getValue(),
                                configurationService.getEnvironment(),
                                CLIENT.getValue(),
                                CLIENT_ID));

        assertAuthCodeExchangeDataRetrieved(authCode);
    }

    @Test
    void shouldReturn400IfRedirectUriDoesNotMatchRedirectUriFromAuthRequest()
            throws JOSEException, TokenAuthInvalidException {
        KeyPair keyPair = generateRsaKeyPair();
        PrivateKeyJWT privateKeyJWT = generatePrivateKeyJWT(keyPair.getPrivate());
        ClientRegistry clientRegistry = generateClientRegistry(keyPair, CLIENT_ID);
        when(tokenService.validateTokenRequestParams(anyString())).thenReturn(Optional.empty());
        when(tokenClientAuthValidatorFactory.getTokenAuthenticationValidator(any()))
                .thenReturn(Optional.of(tokenClientAuthValidator));
        when(tokenClientAuthValidator.validateTokenAuthAndReturnClientRegistryIfValid(
                        anyString(), any()))
                .thenReturn(clientRegistry);
        String authCode = new AuthorizationCode().toString();
        List<VectorOfTrust> vtr = List.of(mock(VectorOfTrust.class));
        var authRequestParams = generateAuthRequest().toParameters();
        setupClientSessions(authCode, authRequestParams, vtr);
        APIGatewayProxyResponseEvent result =
                generateApiGatewayRequest(
                        privateKeyJWT, authCode, "http://invalid-redirect-uri", CLIENT_ID, true);
        assertThat(result, hasStatus(400));
        assertThat(result, hasBody(OAuth2Error.INVALID_GRANT.toJSONObject().toJSONString()));
        verify(cloudwatchMetricsService, never())
                .incrementCounter(
                        SUCCESSFUL_TOKEN_ISSUED.getValue(),
                        Map.of(
                                ENVIRONMENT.getValue(),
                                configurationService.getEnvironment(),
                                CLIENT.getValue(),
                                CLIENT_ID));

        assertAuthCodeExchangeDataRetrieved(authCode);
    }

    @Nested
    class PkceValidation {
        private static final CodeVerifier CODE_VERIFIER = new CodeVerifier();
        private static final String CODE_CHALLENGE_STRING =
                CodeChallenge.compute(CodeChallengeMethod.S256, CODE_VERIFIER).toString();
        private static final String CODE_CHALLENGE_PLAIN_STRING =
                CodeChallenge.compute(CodeChallengeMethod.PLAIN, CODE_VERIFIER).toString();

        @BeforeEach
        void setup() {
            when(configurationService.isPkceEnabled()).thenReturn(true);
        }

        @Test
        void shouldReturn200IfCodeChallengeAndVerifierIsCorrect()
                throws JOSEException, TokenAuthInvalidException {
            KeyPair keyPair = generateRsaKeyPair();
            UserProfile userProfile = generateUserProfile();
            SignedJWT signedJWT =
                    generateIDToken(
                            CLIENT_ID,
                            RP_PAIRWISE_SUBJECT,
                            "issuer-url",
                            new ECKeyGenerator(Curve.P_256)
                                    .algorithm(JWSAlgorithm.ES256)
                                    .generate());
            OIDCTokenResponse tokenResponse =
                    new OIDCTokenResponse(new OIDCTokens(signedJWT, accessToken, refreshToken));
            PrivateKeyJWT privateKeyJWT = generatePrivateKeyJWT(keyPair.getPrivate());
            ClientRegistry clientRegistry = generateClientRegistry(keyPair, CLIENT_ID);

            when(tokenService.validateTokenRequestParams(anyString())).thenReturn(Optional.empty());
            when(tokenClientAuthValidatorFactory.getTokenAuthenticationValidator(any()))
                    .thenReturn(Optional.of(tokenClientAuthValidator));
            when(tokenClientAuthValidator.validateTokenAuthAndReturnClientRegistryIfValid(
                            anyString(), any()))
                    .thenReturn(clientRegistry);
            String authCode = new AuthorizationCode().toString();
            AuthenticationRequest authenticationRequest =
                    generateAuthRequestWithCorrectCodeChallenge();
            List<VectorOfTrust> vtr =
                    VectorOfTrust.parseFromAuthRequestAttribute(
                            authenticationRequest.getCustomParameter("vtr"));
            VectorOfTrust lowestLevelVtr = VectorOfTrust.orderVtrList(vtr).get(0);
            setupClientSessions(authCode, authenticationRequest.toParameters(), vtr);
            when(dynamoService.getUserProfileByEmail(eq(TEST_EMAIL))).thenReturn(userProfile);
            when(tokenService.generateTokenResponse(
                            CLIENT_ID,
                            INTERNAL_SUBJECT,
                            SCOPES,
                            Map.of("nonce", NONCE),
                            RP_PAIRWISE_SUBJECT,
                            INTERNAL_PAIRWISE_SUBJECT,
                            null,
                            false,
                            JWSAlgorithm.ES256,
                            CLIENT_SESSION_ID,
                            lowestLevelVtr.retrieveVectorOfTrustForToken(),
                            AUTH_TIME))
                    .thenReturn(tokenResponse);
            when(configurationService.isPkceEnabled()).thenReturn(true);

            APIGatewayProxyResponseEvent result =
                    generateApiGatewayRequestWithCorrectCodeVerifier(privateKeyJWT, authCode, true);
            assertThat(result, hasStatus(200));
            verify(cloudwatchMetricsService)
                    .incrementCounter(
                            SUCCESSFUL_TOKEN_ISSUED.getValue(),
                            Map.of(
                                    ENVIRONMENT.getValue(),
                                    configurationService.getEnvironment(),
                                    CLIENT.getValue(),
                                    CLIENT_ID));

            assertAuthCodeExchangeDataRetrieved(authCode);
        }

        @Test
        void shouldReturn400IfPkceVerificationFailed()
                throws JOSEException, TokenAuthInvalidException {
            KeyPair keyPair = generateRsaKeyPair();
            PrivateKeyJWT privateKeyJWT = generatePrivateKeyJWT(keyPair.getPrivate());
            ClientRegistry clientRegistry = generateClientRegistry(keyPair, CLIENT_ID);

            when(tokenClientAuthValidatorFactory.getTokenAuthenticationValidator(any()))
                    .thenReturn(Optional.of(tokenClientAuthValidator));
            when(tokenService.validateTokenRequestParams(anyString())).thenReturn(Optional.empty());
            when(tokenClientAuthValidator.validateTokenAuthAndReturnClientRegistryIfValid(
                            anyString(), any()))
                    .thenReturn(clientRegistry);
            String authCode = new AuthorizationCode().toString();
            setupClientSessions(
                    authCode,
                    generateAuthRequestWithCodeChallenge("Incorrect Code Challenge").toParameters(),
                    List.of(mock(VectorOfTrust.class)));

            APIGatewayProxyResponseEvent result =
                    generateApiGatewayRequestWithCorrectCodeVerifier(privateKeyJWT, authCode, true);
            assertThat(result, hasStatus(400));
            assertThat(
                    result,
                    hasBody(
                            new ErrorObject(
                                            OAuth2Error.INVALID_GRANT_CODE,
                                            "PKCE code verification failed")
                                    .toJSONObject()
                                    .toJSONString()));
            verify(cloudwatchMetricsService, never())
                    .incrementCounter(
                            SUCCESSFUL_TOKEN_ISSUED.getValue(),
                            Map.of(
                                    ENVIRONMENT.getValue(),
                                    configurationService.getEnvironment(),
                                    CLIENT.getValue(),
                                    CLIENT_ID));

            assertAuthCodeExchangeDataRetrieved(authCode);
        }

        @Test
        void shouldReturn400IfCodeChallengeMethodPlainIsUsed()
                throws JOSEException, TokenAuthInvalidException {
            KeyPair keyPair = generateRsaKeyPair();
            PrivateKeyJWT privateKeyJWT = generatePrivateKeyJWT(keyPair.getPrivate());
            ClientRegistry clientRegistry = generateClientRegistry(keyPair, CLIENT_ID);

            when(tokenService.validateTokenRequestParams(anyString())).thenReturn(Optional.empty());
            when(tokenClientAuthValidatorFactory.getTokenAuthenticationValidator(any()))
                    .thenReturn(Optional.of(tokenClientAuthValidator));
            when(tokenClientAuthValidator.validateTokenAuthAndReturnClientRegistryIfValid(
                            anyString(), any()))
                    .thenReturn(clientRegistry);
            String authCode = new AuthorizationCode().toString();
            setupClientSessions(
                    authCode,
                    generateAuthRequestWithCodeChallenge(CODE_CHALLENGE_PLAIN_STRING)
                            .toParameters(),
                    List.of(mock(VectorOfTrust.class)));

            APIGatewayProxyResponseEvent result =
                    generateApiGatewayRequestWithCorrectCodeVerifier(privateKeyJWT, authCode, true);
            assertThat(result, hasStatus(400));
            assertThat(
                    result,
                    hasBody(
                            new ErrorObject(
                                            OAuth2Error.INVALID_GRANT_CODE,
                                            "PKCE code verification failed")
                                    .toJSONObject()
                                    .toJSONString()));
            verify(cloudwatchMetricsService, never())
                    .incrementCounter(
                            SUCCESSFUL_TOKEN_ISSUED.getValue(),
                            Map.of(
                                    ENVIRONMENT.getValue(),
                                    configurationService.getEnvironment(),
                                    CLIENT.getValue(),
                                    CLIENT_ID));

            assertAuthCodeExchangeDataRetrieved(authCode);
        }

        @ParameterizedTest
        @MethodSource("invalidCodeVerifiers")
        void shouldReturn400IfCodeVerifierFailsSyntax(String codeVerifier)
                throws JOSEException, TokenAuthInvalidException {
            KeyPair keyPair = generateRsaKeyPair();
            PrivateKeyJWT privateKeyJWT = generatePrivateKeyJWT(keyPair.getPrivate());
            ClientRegistry clientRegistry = generateClientRegistry(keyPair, CLIENT_ID);

            when(tokenClientAuthValidatorFactory.getTokenAuthenticationValidator(any()))
                    .thenReturn(Optional.of(tokenClientAuthValidator));
            when(tokenService.validateTokenRequestParams(anyString())).thenReturn(Optional.empty());
            when(tokenClientAuthValidator.validateTokenAuthAndReturnClientRegistryIfValid(
                            anyString(), any()))
                    .thenReturn(clientRegistry);
            String authCode = new AuthorizationCode().toString();
            setupClientSessions(
                    authCode,
                    generateAuthRequestWithCorrectCodeChallenge().toParameters(),
                    List.of(mock(VectorOfTrust.class)));

            APIGatewayProxyResponseEvent result =
                    generateApiGatewayRequestWithCodeVerifier(
                            privateKeyJWT, authCode, REDIRECT_URI, true, codeVerifier);
            assertThat(result, hasStatus(400));
            assertThat(
                    result,
                    hasBody(
                            new ErrorObject(
                                            OAuth2Error.INVALID_GRANT_CODE,
                                            "PKCE code verification failed")
                                    .toJSONObject()
                                    .toJSONString()));
            verify(cloudwatchMetricsService, never())
                    .incrementCounter(
                            SUCCESSFUL_TOKEN_ISSUED.getValue(),
                            Map.of(
                                    ENVIRONMENT.getValue(),
                                    configurationService.getEnvironment(),
                                    CLIENT.getValue(),
                                    CLIENT_ID));

            assertAuthCodeExchangeDataRetrieved(authCode);
        }

        @Test
        void shouldReturn400IfCodeVerifierDoesNotExistButCodeChallengeDoes()
                throws JOSEException, TokenAuthInvalidException {
            KeyPair keyPair = generateRsaKeyPair();
            PrivateKeyJWT privateKeyJWT = generatePrivateKeyJWT(keyPair.getPrivate());
            ClientRegistry clientRegistry = generateClientRegistry(keyPair, CLIENT_ID);

            when(tokenClientAuthValidatorFactory.getTokenAuthenticationValidator(any()))
                    .thenReturn(Optional.of(tokenClientAuthValidator));
            when(tokenService.validateTokenRequestParams(anyString())).thenReturn(Optional.empty());
            when(tokenClientAuthValidator.validateTokenAuthAndReturnClientRegistryIfValid(
                            anyString(), any()))
                    .thenReturn(clientRegistry);
            String authCode = new AuthorizationCode().toString();
            setupClientSessions(
                    authCode,
                    generateAuthRequestWithCorrectCodeChallenge().toParameters(),
                    List.of(mock(VectorOfTrust.class)));

            APIGatewayProxyResponseEvent result =
                    generateApiGatewayRequestWithCodeVerifier(
                            privateKeyJWT, authCode, REDIRECT_URI, true, null);
            assertThat(result, hasStatus(400));
            assertThat(
                    result,
                    hasBody(
                            new ErrorObject(
                                            OAuth2Error.INVALID_GRANT_CODE,
                                            "PKCE code verification failed")
                                    .toJSONObject()
                                    .toJSONString()));
            verify(cloudwatchMetricsService, never())
                    .incrementCounter(
                            SUCCESSFUL_TOKEN_ISSUED.getValue(),
                            Map.of(
                                    ENVIRONMENT.getValue(),
                                    configurationService.getEnvironment(),
                                    CLIENT.getValue(),
                                    CLIENT_ID));

            assertAuthCodeExchangeDataRetrieved(authCode);
        }

        @Test
        void shouldReturn400IfCodeChallengeDoesNotExistButCodeVerifierDoes()
                throws JOSEException, TokenAuthInvalidException {
            KeyPair keyPair = generateRsaKeyPair();
            SignedJWT signedJWT =
                    generateIDToken(
                            CLIENT_ID,
                            RP_PAIRWISE_SUBJECT,
                            "issuer-url",
                            new ECKeyGenerator(Curve.P_256)
                                    .algorithm(JWSAlgorithm.ES256)
                                    .generate());
            OIDCTokenResponse tokenResponse =
                    new OIDCTokenResponse(new OIDCTokens(signedJWT, accessToken, refreshToken));
            PrivateKeyJWT privateKeyJWT = generatePrivateKeyJWT(keyPair.getPrivate());
            ClientRegistry clientRegistry = generateClientRegistry(keyPair, CLIENT_ID);

            when(tokenService.validateTokenRequestParams(anyString())).thenReturn(Optional.empty());
            when(tokenClientAuthValidatorFactory.getTokenAuthenticationValidator(any()))
                    .thenReturn(Optional.of(tokenClientAuthValidator));
            when(tokenClientAuthValidator.validateTokenAuthAndReturnClientRegistryIfValid(
                            anyString(), any()))
                    .thenReturn(clientRegistry);
            String authCode = new AuthorizationCode().toString();
            AuthenticationRequest authenticationRequest =
                    generateAuthRequestWithCodeChallenge(null);
            List<VectorOfTrust> vtr =
                    VectorOfTrust.parseFromAuthRequestAttribute(
                            authenticationRequest.getCustomParameter("vtr"));
            VectorOfTrust lowestLevelVtr = VectorOfTrust.orderVtrList(vtr).get(0);
            setupClientSessions(authCode, authenticationRequest.toParameters(), vtr);
            when(tokenService.generateTokenResponse(
                            CLIENT_ID,
                            INTERNAL_SUBJECT,
                            SCOPES,
                            Map.of("nonce", NONCE),
                            RP_PAIRWISE_SUBJECT,
                            INTERNAL_PAIRWISE_SUBJECT,
                            null,
                            false,
                            JWSAlgorithm.ES256,
                            CLIENT_SESSION_ID,
                            lowestLevelVtr.retrieveVectorOfTrustForToken(),
                            AUTH_TIME))
                    .thenReturn(tokenResponse);
            when(configurationService.isPkceEnabled()).thenReturn(true);

            APIGatewayProxyResponseEvent result =
                    generateApiGatewayRequestWithCorrectCodeVerifier(privateKeyJWT, authCode, true);
            assertThat(result, hasStatus(400));
            assertThat(
                    result,
                    hasBody(
                            new ErrorObject(
                                            OAuth2Error.INVALID_GRANT_CODE,
                                            "PKCE code verification failed")
                                    .toJSONObject()
                                    .toJSONString()));
            verify(cloudwatchMetricsService, never())
                    .incrementCounter(
                            SUCCESSFUL_TOKEN_ISSUED.getValue(),
                            Map.of(
                                    ENVIRONMENT.getValue(),
                                    configurationService.getEnvironment(),
                                    CLIENT.getValue(),
                                    CLIENT_ID));

            assertAuthCodeExchangeDataRetrieved(authCode);
        }

        @Test
        void shouldNotValidateCodeIfPkceFlagNotEnabled()
                throws JOSEException, TokenAuthInvalidException {
            KeyPair keyPair = generateRsaKeyPair();
            UserProfile userProfile = generateUserProfile();
            SignedJWT signedJWT =
                    generateIDToken(
                            CLIENT_ID,
                            RP_PAIRWISE_SUBJECT,
                            "issuer-url",
                            new ECKeyGenerator(Curve.P_256)
                                    .algorithm(JWSAlgorithm.ES256)
                                    .generate());
            OIDCTokenResponse tokenResponse =
                    new OIDCTokenResponse(new OIDCTokens(signedJWT, accessToken, refreshToken));
            PrivateKeyJWT privateKeyJWT = generatePrivateKeyJWT(keyPair.getPrivate());
            ClientRegistry clientRegistry = generateClientRegistry(keyPair, CLIENT_ID);

            when(tokenService.validateTokenRequestParams(anyString())).thenReturn(Optional.empty());
            when(tokenClientAuthValidatorFactory.getTokenAuthenticationValidator(any()))
                    .thenReturn(Optional.of(tokenClientAuthValidator));
            when(tokenClientAuthValidator.validateTokenAuthAndReturnClientRegistryIfValid(
                            anyString(), any()))
                    .thenReturn(clientRegistry);
            String authCode = new AuthorizationCode().toString();
            AuthenticationRequest authenticationRequest =
                    generateAuthRequestWithCorrectCodeChallenge();
            List<VectorOfTrust> vtr =
                    VectorOfTrust.parseFromAuthRequestAttribute(
                            authenticationRequest.getCustomParameter("vtr"));
            VectorOfTrust lowestLevelVtr = VectorOfTrust.orderVtrList(vtr).get(0);
            setupClientSessions(authCode, authenticationRequest.toParameters(), vtr);
            when(dynamoService.getUserProfileByEmail(eq(TEST_EMAIL))).thenReturn(userProfile);
            when(tokenService.generateTokenResponse(
                            CLIENT_ID,
                            INTERNAL_SUBJECT,
                            SCOPES,
                            Map.of("nonce", NONCE),
                            RP_PAIRWISE_SUBJECT,
                            INTERNAL_PAIRWISE_SUBJECT,
                            null,
                            false,
                            JWSAlgorithm.ES256,
                            CLIENT_SESSION_ID,
                            lowestLevelVtr.retrieveVectorOfTrustForToken(),
                            AUTH_TIME))
                    .thenReturn(tokenResponse);
            when(configurationService.isPkceEnabled()).thenReturn(false);

            APIGatewayProxyResponseEvent result =
                    generateApiGatewayRequestWithCodeVerifier(
                            privateKeyJWT, authCode, REDIRECT_URI, true, "Incorrect-verifier");
            assertThat(result, hasStatus(200));
            verify(cloudwatchMetricsService)
                    .incrementCounter(
                            SUCCESSFUL_TOKEN_ISSUED.getValue(),
                            Map.of(
                                    ENVIRONMENT.getValue(),
                                    configurationService.getEnvironment(),
                                    CLIENT.getValue(),
                                    CLIENT_ID));

            assertAuthCodeExchangeDataRetrieved(authCode);
        }

        @Test
        void shouldNotValidateCodeIfCodeChallengeAndCodeVerifierDoesNotExist()
                throws JOSEException, TokenAuthInvalidException {
            KeyPair keyPair = generateRsaKeyPair();
            UserProfile userProfile = generateUserProfile();
            SignedJWT signedJWT =
                    generateIDToken(
                            CLIENT_ID,
                            RP_PAIRWISE_SUBJECT,
                            "issuer-url",
                            new ECKeyGenerator(Curve.P_256)
                                    .algorithm(JWSAlgorithm.ES256)
                                    .generate());
            OIDCTokenResponse tokenResponse =
                    new OIDCTokenResponse(new OIDCTokens(signedJWT, accessToken, refreshToken));
            PrivateKeyJWT privateKeyJWT = generatePrivateKeyJWT(keyPair.getPrivate());
            ClientRegistry clientRegistry = generateClientRegistry(keyPair, CLIENT_ID);

            when(tokenService.validateTokenRequestParams(anyString())).thenReturn(Optional.empty());
            when(tokenClientAuthValidatorFactory.getTokenAuthenticationValidator(any()))
                    .thenReturn(Optional.of(tokenClientAuthValidator));
            when(tokenClientAuthValidator.validateTokenAuthAndReturnClientRegistryIfValid(
                            anyString(), any()))
                    .thenReturn(clientRegistry);
            String authCode = new AuthorizationCode().toString();
            AuthenticationRequest authenticationRequest =
                    generateAuthRequestWithCodeChallenge(null);
            List<VectorOfTrust> vtr =
                    VectorOfTrust.parseFromAuthRequestAttribute(
                            authenticationRequest.getCustomParameter("vtr"));
            VectorOfTrust lowestLevelVtr = VectorOfTrust.orderVtrList(vtr).get(0);
            setupClientSessions(authCode, authenticationRequest.toParameters(), vtr);
            when(dynamoService.getUserProfileByEmail(eq(TEST_EMAIL))).thenReturn(userProfile);
            when(tokenService.generateTokenResponse(
                            CLIENT_ID,
                            INTERNAL_SUBJECT,
                            SCOPES,
                            Map.of("nonce", NONCE),
                            RP_PAIRWISE_SUBJECT,
                            INTERNAL_PAIRWISE_SUBJECT,
                            null,
                            false,
                            JWSAlgorithm.ES256,
                            CLIENT_SESSION_ID,
                            lowestLevelVtr.retrieveVectorOfTrustForToken(),
                            AUTH_TIME))
                    .thenReturn(tokenResponse);
            when(configurationService.isPkceEnabled()).thenReturn(true);

            APIGatewayProxyResponseEvent result =
                    generateApiGatewayRequest(privateKeyJWT, authCode, CLIENT_ID, true);
            assertThat(result, hasStatus(200));
            verify(cloudwatchMetricsService)
                    .incrementCounter(
                            SUCCESSFUL_TOKEN_ISSUED.getValue(),
                            Map.of(
                                    ENVIRONMENT.getValue(),
                                    configurationService.getEnvironment(),
                                    CLIENT.getValue(),
                                    CLIENT_ID));

            assertAuthCodeExchangeDataRetrieved(authCode);
        }

        // Based off the spec:
        // https://datatracker.ietf.org/doc/html/rfc7636#section-4.1
        private static Stream<String> invalidCodeVerifiers() {
            return Stream.of(
                    "LessThan43Characters",
                    "InvalidCharacters$£!@)(*&^aaaaaaaaaaaaaaaaaaaa",
                    "",
                    "ThisIsOverTheCharacterCount128aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        }

        private AuthenticationRequest generateAuthRequestWithCorrectCodeChallenge() {
            return generateAuthRequestWithCodeChallenge(CODE_CHALLENGE_STRING);
        }

        private AuthenticationRequest generateAuthRequestWithCodeChallenge(String codeChallenge) {
            JSONArray jsonArray = new JSONArray();
            jsonArray.add("Cl.Cm");
            jsonArray.add("Cl");
            ResponseType responseType = new ResponseType(ResponseType.Value.CODE);
            State state = new State();
            return new AuthenticationRequest.Builder(
                            responseType,
                            Scope.parse(SCOPES.toString()),
                            new ClientID(CLIENT_ID),
                            URI.create(REDIRECT_URI))
                    .state(state)
                    .nonce(NONCE)
                    .customParameter("vtr", jsonArray.toJSONString())
                    .customParameter("code_challenge", codeChallenge)
                    .build();
        }

        private APIGatewayProxyResponseEvent generateApiGatewayRequestWithCorrectCodeVerifier(
                PrivateKeyJWT privateKeyJWT, String authorisationCode, boolean clientIdInHeader) {
            return generateApiGatewayRequestWithCodeVerifier(
                    privateKeyJWT,
                    authorisationCode,
                    REDIRECT_URI,
                    clientIdInHeader,
                    CODE_VERIFIER.getValue());
        }

        private APIGatewayProxyResponseEvent generateApiGatewayRequestWithCodeVerifier(
                PrivateKeyJWT privateKeyJWT,
                String authorisationCode,
                String redirectUri,
                boolean clientIdInHeader,
                String codeVerifier) {
            Map<String, List<String>> customParams = new HashMap<>();
            customParams.put(
                    "grant_type",
                    Collections.singletonList(GrantType.AUTHORIZATION_CODE.getValue()));
            if (clientIdInHeader) {
                customParams.put("client_id", Collections.singletonList(IGNORE_CLIENT_ID));
            }
            customParams.put("code", Collections.singletonList(authorisationCode));
            customParams.put("redirect_uri", Collections.singletonList(redirectUri));
            customParams.put("code_verifier", Collections.singletonList(codeVerifier));
            Map<String, List<String>> privateKeyParams = privateKeyJWT.toParameters();
            privateKeyParams.putAll(customParams);
            String requestParams = URLUtils.serializeParameters(privateKeyParams);
            APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
            event.setBody(requestParams);
            return handler.handleRequest(event, context);
        }
    }

    @Test
    void shouldReturn200ForSuccessfulDocAppJourneyTokenRequest()
            throws JOSEException, TokenAuthInvalidException {
        KeyPair keyPair = generateRsaKeyPair();
        UserProfile userProfile = generateUserProfile();
        SignedJWT signedJWT =
                generateIDToken(
                        DOC_APP_CLIENT_ID.getValue(),
                        RP_PAIRWISE_SUBJECT,
                        "issuer-url",
                        new ECKeyGenerator(Curve.P_256).algorithm(JWSAlgorithm.ES256).generate());
        OIDCTokenResponse tokenResponse =
                new OIDCTokenResponse(new OIDCTokens(signedJWT, accessToken, refreshToken));
        PrivateKeyJWT privateKeyJWT = generatePrivateKeyJWT(keyPair.getPrivate());
        ClientRegistry clientRegistry =
                generateClientRegistry(keyPair, DOC_APP_CLIENT_ID.getValue());

        when(tokenService.validateTokenRequestParams(anyString())).thenReturn(Optional.empty());
        when(tokenClientAuthValidatorFactory.getTokenAuthenticationValidator(any()))
                .thenReturn(Optional.of(tokenClientAuthValidator));
        when(tokenClientAuthValidator.validateTokenAuthAndReturnClientRegistryIfValid(
                        anyString(), any()))
                .thenReturn(clientRegistry);
        String authCode = new AuthorizationCode().toString();
        AuthorizationRequest authenticationRequest = generateRequestObjectAuthRequest();
        List<VectorOfTrust> vtr =
                VectorOfTrust.parseFromAuthRequestAttribute(
                        authenticationRequest.getCustomParameter("vtr"));
        VectorOfTrust lowestLevelVtr = VectorOfTrust.orderVtrList(vtr).get(0);
        setupClientSessions(
                authCode,
                authenticationRequest.toParameters(),
                vtr,
                DOC_APP_CLIENT_ID.getValue(),
                DOC_APP_USER_PUBLIC_SUBJECT);
        when(dynamoService.getUserProfileByEmail(TEST_EMAIL)).thenReturn(userProfile);
        when(tokenService.generateTokenResponse(
                        DOC_APP_CLIENT_ID.getValue(),
                        DOC_APP_USER_PUBLIC_SUBJECT,
                        new Scope(DOC_CHECKING_APP, OIDCScopeValue.OPENID),
                        Map.of("nonce", NONCE),
                        DOC_APP_USER_PUBLIC_SUBJECT,
                        DOC_APP_USER_PUBLIC_SUBJECT,
                        null,
                        true,
                        JWSAlgorithm.ES256,
                        CLIENT_SESSION_ID,
                        lowestLevelVtr.retrieveVectorOfTrustForToken(),
                        null))
                .thenReturn(tokenResponse);

        var result =
                generateApiGatewayRequest(
                        privateKeyJWT, authCode, DOC_APP_CLIENT_ID.getValue(), true);

        assertThat(result, hasStatus(200));
        assertTrue(result.getBody().contains(refreshToken.getValue()));
        assertTrue(result.getBody().contains(accessToken.getValue()));
        verify(cloudwatchMetricsService)
                .incrementCounter(
                        SUCCESSFUL_TOKEN_ISSUED.getValue(),
                        Map.of(
                                ENVIRONMENT.getValue(),
                                configurationService.getEnvironment(),
                                CLIENT.getValue(),
                                DOC_APP_CLIENT_ID.getValue()));

        assertAuthCodeExchangeDataRetrieved(authCode);
    }

    private static Stream<Arguments> vectorsTypesThatShouldNotReturnClaims() {
        return Stream.of(Arguments.of("Cl.Cm"), Arguments.of("Cl"), Arguments.of("P0.Cl.Cm"));
    }

    @ParameterizedTest
    @MethodSource("vectorsTypesThatShouldNotReturnClaims")
    void shouldNotReturnClaimsForNonIdentityJourneys(String vectorValue)
            throws JOSEException, TokenAuthInvalidException {
        when(configurationService.isRsaSigningAvailable()).thenReturn(true);

        KeyPair keyPair = generateRsaKeyPair();
        UserProfile userProfile = generateUserProfile();
        SignedJWT signedJWT =
                generateIDToken(
                        CLIENT_ID,
                        RP_PAIRWISE_SUBJECT,
                        "issuer-url",
                        new RSAKeyGenerator(2048).algorithm(JWSAlgorithm.RS256).generate());
        OIDCTokenResponse tokenResponse =
                new OIDCTokenResponse(new OIDCTokens(signedJWT, accessToken, refreshToken));
        PrivateKeyJWT privateKeyJWT = generatePrivateKeyJWT(keyPair.getPrivate());
        ClientRegistry clientRegistry =
                generateClientRegistry(keyPair, CLIENT_ID)
                        .withIdTokenSigningAlgorithm(JWSAlgorithm.RS256.getName());

        when(tokenService.validateTokenRequestParams(anyString())).thenReturn(Optional.empty());
        when(tokenClientAuthValidatorFactory.getTokenAuthenticationValidator(any()))
                .thenReturn(Optional.of(tokenClientAuthValidator));
        when(tokenClientAuthValidator.validateTokenAuthAndReturnClientRegistryIfValid(
                        anyString(), any()))
                .thenReturn(clientRegistry);
        String authCode = new AuthorizationCode().toString();
        var claimsSetRequest = new ClaimsSetRequest().add("nickname").add("birthdate");
        var oidcClaimsRequest = new OIDCClaimsRequest().withUserInfoClaimsRequest(claimsSetRequest);
        AuthenticationRequest authenticationRequest =
                generateRequestObjectAuthRequestWithOIDCClaims(
                        JsonArrayHelper.jsonArrayOf(vectorValue), oidcClaimsRequest);
        List<VectorOfTrust> vtr =
                VectorOfTrust.parseFromAuthRequestAttribute(
                        authenticationRequest.getCustomParameter("vtr"));
        VectorOfTrust lowestLevelVtr = VectorOfTrust.orderVtrList(vtr).get(0);
        setupClientSessions(authCode, authenticationRequest.toParameters(), vtr);
        when(dynamoService.getUserProfileByEmail(eq(TEST_EMAIL))).thenReturn(userProfile);
        when(tokenService.generateTokenResponse(
                        eq(CLIENT_ID),
                        eq(INTERNAL_SUBJECT),
                        eq(SCOPES),
                        eq(Map.of("nonce", NONCE)),
                        eq(RP_PAIRWISE_SUBJECT),
                        eq(INTERNAL_PAIRWISE_SUBJECT),
                        eq(null),
                        eq(false),
                        eq(JWSAlgorithm.RS256),
                        eq(CLIENT_SESSION_ID),
                        eq(lowestLevelVtr.retrieveVectorOfTrustForToken()),
                        eq(AUTH_TIME)))
                .thenReturn(tokenResponse);

        APIGatewayProxyResponseEvent result =
                generateApiGatewayRequest(privateKeyJWT, authCode, CLIENT_ID, true);
        assertThat(result, hasStatus(200));
        assertTrue(result.getBody().contains(refreshToken.getValue()));
        assertTrue(result.getBody().contains(accessToken.getValue()));
        assertClaimsRequestIfPresent(oidcClaimsRequest, false);

        assertAuthCodeExchangeDataRetrieved(authCode);
    }

    @Test
    void shouldReturnClaimsForIdentityJourney() throws JOSEException, TokenAuthInvalidException {
        when(configurationService.isRsaSigningAvailable()).thenReturn(true);

        KeyPair keyPair = generateRsaKeyPair();
        UserProfile userProfile = generateUserProfile();
        SignedJWT signedJWT =
                generateIDToken(
                        CLIENT_ID,
                        RP_PAIRWISE_SUBJECT,
                        "issuer-url",
                        new RSAKeyGenerator(2048).algorithm(JWSAlgorithm.RS256).generate());
        OIDCTokenResponse tokenResponse =
                new OIDCTokenResponse(new OIDCTokens(signedJWT, accessToken, refreshToken));
        PrivateKeyJWT privateKeyJWT = generatePrivateKeyJWT(keyPair.getPrivate());
        ClientRegistry clientRegistry =
                generateClientRegistry(keyPair, CLIENT_ID)
                        .withIdTokenSigningAlgorithm(JWSAlgorithm.RS256.getName());

        when(tokenService.validateTokenRequestParams(anyString())).thenReturn(Optional.empty());
        when(tokenClientAuthValidatorFactory.getTokenAuthenticationValidator(any()))
                .thenReturn(Optional.of(tokenClientAuthValidator));
        when(tokenClientAuthValidator.validateTokenAuthAndReturnClientRegistryIfValid(
                        anyString(), any()))
                .thenReturn(clientRegistry);
        String authCode = new AuthorizationCode().toString();
        var claimsSetRequest = new ClaimsSetRequest().add("nickname").add("birthdate");
        var oidcClaimsRequest = new OIDCClaimsRequest().withUserInfoClaimsRequest(claimsSetRequest);
        AuthenticationRequest authenticationRequest =
                generateRequestObjectAuthRequestWithOIDCClaims(
                        JsonArrayHelper.jsonArrayOf("P2.Cl.Cm"), oidcClaimsRequest);
        List<VectorOfTrust> vtr =
                VectorOfTrust.parseFromAuthRequestAttribute(
                        authenticationRequest.getCustomParameter("vtr"));
        VectorOfTrust lowestLevelVtr = VectorOfTrust.orderVtrList(vtr).get(0);
        setupClientSessions(authCode, authenticationRequest.toParameters(), vtr);
        when(dynamoService.getUserProfileByEmail(eq(TEST_EMAIL))).thenReturn(userProfile);
        when(tokenService.generateTokenResponse(
                        eq(CLIENT_ID),
                        eq(INTERNAL_SUBJECT),
                        eq(SCOPES),
                        eq(Map.of("nonce", NONCE)),
                        eq(RP_PAIRWISE_SUBJECT),
                        eq(INTERNAL_PAIRWISE_SUBJECT),
                        argThat(
                                (actualOidcClaimsRequest) ->
                                        actualOidcClaimsRequest
                                                .toJSONString()
                                                .equals(oidcClaimsRequest.toJSONString())),
                        eq(false),
                        eq(JWSAlgorithm.RS256),
                        eq(CLIENT_SESSION_ID),
                        eq(lowestLevelVtr.retrieveVectorOfTrustForToken()),
                        eq(AUTH_TIME)))
                .thenReturn(tokenResponse);

        APIGatewayProxyResponseEvent result =
                generateApiGatewayRequest(privateKeyJWT, authCode, CLIENT_ID, true);
        assertThat(result, hasStatus(200));
        assertTrue(result.getBody().contains(refreshToken.getValue()));
        assertTrue(result.getBody().contains(accessToken.getValue()));
        assertClaimsRequestIfPresent(oidcClaimsRequest, true);
    }

    @Test
    void shouldReturn500ForTokenRequestIfOrchAuthCodeGetExchangeDataThrowsException()
            throws JOSEException, TokenAuthInvalidException {
        KeyPair keyPair = generateRsaKeyPair();
        UserProfile userProfile = generateUserProfile();
        SignedJWT signedJWT =
                generateIDToken(
                        CLIENT_ID,
                        RP_PAIRWISE_SUBJECT,
                        "issuer-url",
                        new ECKeyGenerator(Curve.P_256).algorithm(JWSAlgorithm.ES256).generate());
        OIDCTokenResponse tokenResponse =
                new OIDCTokenResponse(new OIDCTokens(signedJWT, accessToken, refreshToken));
        PrivateKeyJWT privateKeyJWT = generatePrivateKeyJWT(keyPair.getPrivate());
        ClientRegistry clientRegistry = generateClientRegistry(keyPair, CLIENT_ID);

        when(tokenService.validateTokenRequestParams(anyString())).thenReturn(Optional.empty());
        when(tokenClientAuthValidatorFactory.getTokenAuthenticationValidator(any()))
                .thenReturn(Optional.of(tokenClientAuthValidator));
        when(tokenClientAuthValidator.validateTokenAuthAndReturnClientRegistryIfValid(
                        anyString(), any()))
                .thenReturn(clientRegistry);
        String authCode = new AuthorizationCode().toString();
        AuthenticationRequest authenticationRequest = generateAuthRequest();
        List<VectorOfTrust> vtr =
                VectorOfTrust.parseFromAuthRequestAttribute(
                        authenticationRequest.getCustomParameter("vtr"));
        VectorOfTrust lowestLevelVtr = VectorOfTrust.orderVtrList(vtr).get(0);
        setupClientSessions(authCode, authenticationRequest.toParameters(), vtr);
        when(dynamoService.getUserProfileByEmail(eq(TEST_EMAIL))).thenReturn(userProfile);
        when(tokenService.generateTokenResponse(
                        CLIENT_ID,
                        INTERNAL_SUBJECT,
                        SCOPES,
                        Map.of("nonce", NONCE),
                        RP_PAIRWISE_SUBJECT,
                        INTERNAL_PAIRWISE_SUBJECT,
                        null,
                        false,
                        JWSAlgorithm.ES256,
                        CLIENT_SESSION_ID,
                        lowestLevelVtr.retrieveVectorOfTrustForToken(),
                        AUTH_TIME))
                .thenReturn(tokenResponse);

        when(orchAuthCodeService.getExchangeDataForCode(authCode))
                .thenThrow(
                        new RuntimeException(
                                "Some unchecked exception during orch auth code exchange data retrieval."));

        APIGatewayProxyResponseEvent result =
                generateApiGatewayRequest(privateKeyJWT, authCode, CLIENT_ID, true);

        assertThat(result, hasStatus(500));
        assertThat(result, hasBody("Internal server error"));
        verify(cloudwatchMetricsService, never())
                .incrementCounter(eq(SUCCESSFUL_TOKEN_ISSUED.getValue()), anyMap());

        assertAuthCodeExchangeDataRetrieved(authCode);
    }

    private void setupClientSessions(
            String authCode, Map<String, List<String>> authRequestParams, List<VectorOfTrust> vtr) {
        setupClientSessions(authCode, authRequestParams, vtr, CLIENT_ID, null);
    }

    private void setupClientSessions(
            String authCode,
            Map<String, List<String>> authRequestParams,
            List<VectorOfTrust> vtr,
            String clientId,
            Subject docAppSubjectId) {
        AuthCodeExchangeData authCodeExchangeData =
                new AuthCodeExchangeData()
                        .setEmail(TEST_EMAIL)
                        .setClientSessionId(CLIENT_SESSION_ID)
                        .setAuthTime(AUTH_TIME)
                        .setClientId(clientId);
        when(orchAuthCodeService.getExchangeDataForCode(authCode))
                .thenReturn(Optional.of(authCodeExchangeData));
        var orchClientSession =
                new OrchClientSessionItem(
                        CLIENT_SESSION_ID,
                        authRequestParams,
                        clientSessionCreationTime,
                        vtr,
                        CLIENT_NAME);
        Optional.ofNullable(docAppSubjectId)
                .ifPresent(subject -> orchClientSession.setDocAppSubjectId(subject.getValue()));
        when(orchClientSessionService.getClientSession(CLIENT_SESSION_ID))
                .thenReturn(Optional.of(orchClientSession));
    }

    private void setupNoClientSessions() {
        AuthCodeExchangeData authCodeExchangeData =
                new AuthCodeExchangeData()
                        .setEmail(TEST_EMAIL)
                        .setClientSessionId(CLIENT_SESSION_ID)
                        .setAuthTime(AUTH_TIME)
                        .setClientId(CLIENT_ID);
        when(orchAuthCodeService.getExchangeDataForCode(anyString()))
                .thenReturn(Optional.of(authCodeExchangeData));
        when(orchClientSessionService.getClientSession(CLIENT_SESSION_ID))
                .thenReturn(Optional.empty());
    }

    private UserProfile generateUserProfile() {
        return new UserProfile()
                .withEmail(TEST_EMAIL)
                .withEmailVerified(true)
                .withPhoneNumber(PHONE_NUMBER)
                .withPhoneNumberVerified(true)
                .withSubjectID(INTERNAL_SUBJECT.getValue())
                .withCreated(LocalDateTime.now().toString())
                .withUpdated(LocalDateTime.now().toString())
                .withPublicSubjectID(new Subject().getValue())
                .withSalt(SALT);
    }

    private SignedJWT createSignedRefreshToken() throws JOSEException {
        ECKey ecSigningKey =
                new ECKeyGenerator(Curve.P_256)
                        .keyID("KEY_ID")
                        .algorithm(JWSAlgorithm.ES256)
                        .generate();
        ECDSASigner signer = new ECDSASigner(ecSigningKey);
        return TokenGeneratorHelper.generateSignedToken(
                CLIENT_ID, BASE_URI, SCOPES.toStringList(), signer, RP_PAIRWISE_SUBJECT, "KEY_ID");
    }

    private SignedJWT createSignedRsaRefreshToken() throws JOSEException {
        JWSSigner signer =
                new RSASSASigner(
                        new RSAKeyGenerator(2048).algorithm(JWSAlgorithm.RS256).generate());
        return TokenGeneratorHelper.generateSignedToken(
                CLIENT_ID, BASE_URI, SCOPES.toStringList(), signer, RP_PAIRWISE_SUBJECT, "KEY_ID");
    }

    private PrivateKeyJWT generatePrivateKeyJWT(PrivateKey privateKey) throws JOSEException {
        return new PrivateKeyJWT(
                new ClientID(CLIENT_ID),
                URI.create(TOKEN_URI),
                JWSAlgorithm.RS256,
                privateKey,
                null,
                null);
    }

    private ClientRegistry generateClientRegistry(KeyPair keyPair, String clientID) {
        return new ClientRegistry()
                .withClientID(clientID)
                .withClientName("test-client")
                .withRedirectUrls(singletonList(REDIRECT_URI))
                .withScopes(SCOPES.toStringList())
                .withContacts(singletonList(TEST_EMAIL))
                .withPublicKey(
                        Base64.getMimeEncoder().encodeToString(keyPair.getPublic().getEncoded()))
                .withSectorIdentifierUri(RP_SECTOR_URI)
                .withSubjectType("pairwise");
    }

    private APIGatewayProxyResponseEvent generateApiGatewayRequest(
            PrivateKeyJWT privateKeyJWT,
            String authorisationCode,
            String redirectUri,
            String clientId,
            boolean clientIdInHeader) {
        Map<String, List<String>> customParams = new HashMap<>();
        customParams.put(
                "grant_type", Collections.singletonList(GrantType.AUTHORIZATION_CODE.getValue()));
        if (clientIdInHeader) {
            customParams.put("client_id", Collections.singletonList(IGNORE_CLIENT_ID));
        }
        customParams.put("code", Collections.singletonList(authorisationCode));
        customParams.put("redirect_uri", Collections.singletonList(redirectUri));
        Map<String, List<String>> privateKeyParams = privateKeyJWT.toParameters();
        privateKeyParams.putAll(customParams);
        String requestParams = URLUtils.serializeParameters(privateKeyParams);
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody(requestParams);
        return handler.handleRequest(event, context);
    }

    private APIGatewayProxyResponseEvent generateApiGatewayRefreshRequest(
            PrivateKeyJWT privateKeyJWT, String refreshToken, String clientId) {
        Map<String, List<String>> customParams = new HashMap<>();
        customParams.put(
                "grant_type", Collections.singletonList(GrantType.REFRESH_TOKEN.getValue()));
        if (clientId != null) {
            customParams.put("client_id", Collections.singletonList(clientId));
        }
        customParams.put("refresh_token", Collections.singletonList(refreshToken));
        Map<String, List<String>> privateKeyParams = privateKeyJWT.toParameters();
        privateKeyParams.putAll(customParams);
        String requestParams = URLUtils.serializeParameters(privateKeyParams);
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody(requestParams);
        return handler.handleRequest(event, context);
    }

    private APIGatewayProxyResponseEvent generateApiGatewayRequest(
            PrivateKeyJWT privateKeyJWT,
            String authorisationCode,
            String clientId,
            boolean clientIdInHeader) {
        return generateApiGatewayRequest(
                privateKeyJWT, authorisationCode, REDIRECT_URI, clientId, clientIdInHeader);
    }

    private AuthenticationRequest generateAuthRequest() {
        JSONArray jsonArray = new JSONArray();
        jsonArray.add("Cl.Cm");
        jsonArray.add("Cl");
        return generateAuthRequest(jsonArray.toJSONString());
    }

    private AuthenticationRequest generateAuthRequest(String vtr) {
        ResponseType responseType = new ResponseType(ResponseType.Value.CODE);
        State state = new State();
        return new AuthenticationRequest.Builder(
                        responseType,
                        Scope.parse(SCOPES.toString()),
                        new ClientID(CLIENT_ID),
                        URI.create(REDIRECT_URI))
                .state(state)
                .nonce(NONCE)
                .customParameter("vtr", vtr)
                .build();
    }

    private KeyPair generateRsaKeyPair() {
        KeyPairGenerator kpg;
        try {
            kpg = KeyPairGenerator.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException();
        }
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }

    private static AuthenticationRequest generateRequestObjectAuthRequest() throws JOSEException {
        var keyPair = KeyPairUtils.generateRsaKeyPair();
        Scope scope = new Scope(DOC_CHECKING_APP, OIDCScopeValue.OPENID);
        var jwtClaimsSet =
                new JWTClaimsSet.Builder()
                        .audience(AUDIENCE)
                        .claim("redirect_uri", REDIRECT_URI)
                        .claim("response_type", ResponseType.CODE.toString())
                        .claim("scope", scope.toString())
                        .claim("client_id", DOC_APP_CLIENT_ID.getValue())
                        .claim("state", STATE.getValue())
                        .claim("nonce", NONCE.getValue())
                        .issuer(CLIENT_ID)
                        .build();
        var signedJWT = generateSignedJWT(jwtClaimsSet, keyPair);
        return generateAuthRequest(signedJWT);
    }

    private static AuthenticationRequest generateRequestObjectAuthRequestWithOIDCClaims(
            String vtr, OIDCClaimsRequest oidcClaimsRequest) {
        ResponseType responseType = new ResponseType(ResponseType.Value.CODE);
        State state = new State();
        return new AuthenticationRequest.Builder(
                        responseType,
                        Scope.parse(SCOPES.toString()),
                        new ClientID(CLIENT_ID),
                        URI.create(REDIRECT_URI))
                .state(state)
                .nonce(NONCE)
                .claims(oidcClaimsRequest)
                .customParameter("vtr", vtr)
                .build();
    }

    private static AuthenticationRequest generateAuthRequest(SignedJWT signedJWT) {
        Scope scope = new Scope(DOC_CHECKING_APP, OIDCScopeValue.OPENID);
        return new AuthenticationRequest.Builder(
                        ResponseType.CODE, scope, DOC_APP_CLIENT_ID, URI.create(REDIRECT_URI))
                .state(STATE)
                .nonce(NONCE)
                .requestObject(signedJWT)
                .build();
    }

    private void assertClaimsRequestIfPresent(
            OIDCClaimsRequest oidcClaimsRequest, boolean returningClaims) {
        var finalClaimsRequestCaptor = ArgumentCaptor.forClass(OIDCClaimsRequest.class);
        verify(tokenService)
                .generateTokenResponse(
                        any(),
                        any(),
                        any(),
                        any(),
                        any(),
                        any(),
                        finalClaimsRequestCaptor.capture(),
                        anyBoolean(),
                        any(),
                        any(),
                        any(),
                        any());
        if (returningClaims) {
            assertEquals(
                    oidcClaimsRequest.toJSONString(),
                    finalClaimsRequestCaptor.getValue().toJSONString());
        } else {
            assertEquals(null, finalClaimsRequestCaptor.getValue());
        }
    }

    private void assertAuthCodeExchangeDataRetrieved(String authCode) {
        verify(orchAuthCodeService, times(1)).getExchangeDataForCode(eq(authCode));
    }
}
