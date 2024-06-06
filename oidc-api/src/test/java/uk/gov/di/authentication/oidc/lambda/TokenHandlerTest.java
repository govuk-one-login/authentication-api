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
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.oauth2.sdk.util.URLUtils;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import net.minidev.json.JSONArray;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;
import uk.gov.di.orchestration.shared.entity.AuthCodeExchangeData;
import uk.gov.di.orchestration.shared.entity.ClientRegistry;
import uk.gov.di.orchestration.shared.entity.ClientSession;
import uk.gov.di.orchestration.shared.entity.RefreshTokenStore;
import uk.gov.di.orchestration.shared.entity.UserProfile;
import uk.gov.di.orchestration.shared.entity.VtrList;
import uk.gov.di.orchestration.shared.exceptions.TokenAuthInvalidException;
import uk.gov.di.orchestration.shared.helpers.ClientSubjectHelper;
import uk.gov.di.orchestration.shared.serialization.Json;
import uk.gov.di.orchestration.shared.services.AuthorisationCodeService;
import uk.gov.di.orchestration.shared.services.ClientSessionService;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.DynamoService;
import uk.gov.di.orchestration.shared.services.RedisConnectionService;
import uk.gov.di.orchestration.shared.services.SerializationService;
import uk.gov.di.orchestration.shared.services.TokenService;
import uk.gov.di.orchestration.shared.services.TokenValidationService;
import uk.gov.di.orchestration.shared.validation.TokenClientAuthValidator;
import uk.gov.di.orchestration.shared.validation.TokenClientAuthValidatorFactory;
import uk.gov.di.orchestration.sharedtest.helper.JsonArrayHelper;
import uk.gov.di.orchestration.sharedtest.helper.KeyPairHelper;
import uk.gov.di.orchestration.sharedtest.helper.TokenGeneratorHelper;

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
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.oidc.helper.RequestObjectTestHelper.generateSignedJWT;
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
    private final AuthorisationCodeService authorisationCodeService =
            mock(AuthorisationCodeService.class);
    private final ClientSessionService clientSessionService = mock(ClientSessionService.class);
    private final RedisConnectionService redisConnectionService =
            mock(RedisConnectionService.class);
    private TokenHandler handler;
    private final Json objectMapper = SerializationService.getInstance();

    @BeforeEach
    void setUp() {
        when(configurationService.getInternalSectorURI()).thenReturn(INTERNAL_SECTOR_URI);
        when(configurationService.getSessionExpiry()).thenReturn(1234L);
        when(dynamoService.getOrGenerateSalt(any())).thenCallRealMethod();
        handler =
                new TokenHandler(
                        tokenService,
                        dynamoService,
                        configurationService,
                        authorisationCodeService,
                        clientSessionService,
                        tokenValidationService,
                        redisConnectionService,
                        tokenClientAuthValidatorFactory);
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
        VtrList vtr =
                VtrList.parseFromAuthRequestAttribute(
                        authenticationRequest.getCustomParameter("vtr"));
        when(authorisationCodeService.getExchangeDataForCode(authCode))
                .thenReturn(
                        Optional.of(
                                new AuthCodeExchangeData()
                                        .setEmail(TEST_EMAIL)
                                        .setClientSessionId(CLIENT_SESSION_ID)
                                        .setClientSession(
                                                new ClientSession(
                                                        authenticationRequest.toParameters(),
                                                        LocalDateTime.now(),
                                                        vtr,
                                                        CLIENT_NAME))));
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
                        vtr.getCredentialTrustLevel()))
                .thenReturn(tokenResponse);

        APIGatewayProxyResponseEvent result =
                generateApiGatewayRequest(privateKeyJWT, authCode, CLIENT_ID, clientIdInHeader);
        assertThat(result, hasStatus(200));
        assertTrue(result.getBody().contains(refreshToken.getValue()));
        assertTrue(result.getBody().contains(accessToken.getValue()));
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
        VtrList vtr =
                VtrList.parseFromAuthRequestAttribute(
                        authenticationRequest.getCustomParameter("vtr"));
        when(authorisationCodeService.getExchangeDataForCode(authCode))
                .thenReturn(
                        Optional.of(
                                new AuthCodeExchangeData()
                                        .setEmail(TEST_EMAIL)
                                        .setClientSessionId(CLIENT_SESSION_ID)
                                        .setClientSession(
                                                new ClientSession(
                                                        authenticationRequest.toParameters(),
                                                        LocalDateTime.now(),
                                                        vtr,
                                                        CLIENT_NAME))));
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
                        vtr.getCredentialTrustLevel()))
                .thenReturn(tokenResponse);

        APIGatewayProxyResponseEvent result =
                generateApiGatewayRequest(privateKeyJWT, authCode, CLIENT_ID, clientIdInHeader);
        assertThat(result, hasStatus(200));
        assertTrue(result.getBody().contains(refreshToken.getValue()));
        assertTrue(result.getBody().contains(accessToken.getValue()));
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
                new OIDCTokenResponse(new OIDCTokens(accessToken, refreshToken));
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
        when(authorisationCodeService.getExchangeDataForCode(authCode))
                .thenReturn(Optional.empty());

        APIGatewayProxyResponseEvent result =
                generateApiGatewayRequest(privateKeyJWT, authCode, CLIENT_ID, true);
        assertThat(result, hasStatus(400));
        assertThat(result, hasBody(OAuth2Error.INVALID_GRANT.toJSONObject().toJSONString()));
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
        when(authorisationCodeService.getExchangeDataForCode(authCode))
                .thenReturn(
                        Optional.of(
                                new AuthCodeExchangeData()
                                        .setEmail(TEST_EMAIL)
                                        .setClientSessionId(CLIENT_SESSION_ID)
                                        .setClientSession(
                                                new ClientSession(
                                                        generateAuthRequest().toParameters(),
                                                        LocalDateTime.now(),
                                                        VtrList.DEFAULT_VTR_LIST,
                                                        CLIENT_NAME))));

        APIGatewayProxyResponseEvent result =
                generateApiGatewayRequest(
                        privateKeyJWT, authCode, "http://invalid-redirect-uri", CLIENT_ID, true);
        assertThat(result, hasStatus(400));
        assertThat(result, hasBody(OAuth2Error.INVALID_GRANT.toJSONObject().toJSONString()));
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
        VtrList vtr =
                VtrList.parseFromAuthRequestAttribute(
                        authenticationRequest.getCustomParameter("vtr"));
        ClientSession clientSession =
                new ClientSession(
                        authenticationRequest.toParameters(),
                        LocalDateTime.now(),
                        vtr,
                        CLIENT_NAME);
        clientSession.setDocAppSubjectId(DOC_APP_USER_PUBLIC_SUBJECT);
        when(authorisationCodeService.getExchangeDataForCode(authCode))
                .thenReturn(
                        Optional.of(
                                new AuthCodeExchangeData()
                                        .setEmail(TEST_EMAIL)
                                        .setClientSessionId(CLIENT_SESSION_ID)
                                        .setClientSession(clientSession)));
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
                        vtr.getCredentialTrustLevel()))
                .thenReturn(tokenResponse);

        var result =
                generateApiGatewayRequest(
                        privateKeyJWT, authCode, DOC_APP_CLIENT_ID.getValue(), true);

        assertThat(result, hasStatus(200));
        assertTrue(result.getBody().contains(refreshToken.getValue()));
        assertTrue(result.getBody().contains(accessToken.getValue()));
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
        var keyPair = KeyPairHelper.GENERATE_RSA_KEY_PAIR();
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

    private static AuthenticationRequest generateAuthRequest(SignedJWT signedJWT) {
        Scope scope = new Scope(DOC_CHECKING_APP, OIDCScopeValue.OPENID);
        return new AuthenticationRequest.Builder(
                        ResponseType.CODE, scope, DOC_APP_CLIENT_ID, URI.create(REDIRECT_URI))
                .state(STATE)
                .nonce(NONCE)
                .requestObject(signedJWT)
                .build();
    }
}
