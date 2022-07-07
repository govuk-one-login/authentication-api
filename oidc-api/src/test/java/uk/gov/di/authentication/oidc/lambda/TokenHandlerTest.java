package uk.gov.di.authentication.oidc.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
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
import uk.gov.di.authentication.shared.entity.AuthCodeExchangeData;
import uk.gov.di.authentication.shared.entity.ClientConsent;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.ClientSession;
import uk.gov.di.authentication.shared.entity.RefreshTokenStore;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.entity.ValidScopes;
import uk.gov.di.authentication.shared.entity.VectorOfTrust;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.AuthorisationCodeService;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.RedisConnectionService;
import uk.gov.di.authentication.shared.services.SerializationService;
import uk.gov.di.authentication.shared.services.TokenService;
import uk.gov.di.authentication.shared.services.TokenValidationService;
import uk.gov.di.authentication.sharedtest.helper.JsonArrayHelper;
import uk.gov.di.authentication.sharedtest.helper.KeyPairHelper;
import uk.gov.di.authentication.sharedtest.helper.TokenGeneratorHelper;

import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.text.ParseException;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Stream;

import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.oidc.helper.RequestObjectTestHelper.generateSignedJWT;
import static uk.gov.di.authentication.shared.entity.CustomScopeValue.DOC_CHECKING_APP;
import static uk.gov.di.authentication.sharedtest.helper.TokenGeneratorHelper.generateIDToken;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

public class TokenHandlerTest {

    private static final String TEST_EMAIL = "joe.bloggs@digital.cabinet-office.gov.uk";
    private static final String PHONE_NUMBER = "01234567890";
    private static final String REDIRECT_URI = "http://localhost/redirect";
    private static final Subject INTERNAL_SUBJECT = new Subject();
    private static final Subject PUBLIC_SUBJECT = new Subject();
    private static final Subject DOC_APP_USER_PUBLIC_SUBJECT = new Subject();
    private static final String AUDIENCE = "oidc-audience";
    private static final State STATE = new State();
    private static final String CLIENT_ID = "test-id";
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
    private final ClientService clientService = mock(ClientService.class);
    private final TokenValidationService tokenValidationService =
            mock(TokenValidationService.class);
    private final AuthorisationCodeService authorisationCodeService =
            mock(AuthorisationCodeService.class);
    private final ClientSessionService clientSessionService = mock(ClientSessionService.class);
    private final RedisConnectionService redisConnectionService =
            mock(RedisConnectionService.class);
    private TokenHandler handler;
    private final Json objectMapper = SerializationService.getInstance();

    @BeforeEach
    public void setUp() {
        when(configurationService.getOidcApiBaseURL()).thenReturn(Optional.of(BASE_URI));
        when(configurationService.getSessionExpiry()).thenReturn(1234L);
        handler =
                new TokenHandler(
                        clientService,
                        tokenService,
                        dynamoService,
                        configurationService,
                        authorisationCodeService,
                        clientSessionService,
                        tokenValidationService,
                        redisConnectionService);
    }

    private static Stream<Arguments> validVectorValues() {
        return Stream.of(
                Arguments.of("Cl.Cm", true, true, true),
                Arguments.of("Cl", true, true, true),
                Arguments.of("P2.Cl.Cm", true, false, true),
                Arguments.of("P2.Cl", true, false, true),
                Arguments.of("Cl.Cm", false, false, true),
                Arguments.of("Cl", false, false, true),
                Arguments.of("P2.Cl.Cm", false, false, true),
                Arguments.of("P2.Cl", false, false, false),
                Arguments.of("Cl.Cm", true, true, false),
                Arguments.of("Cl", true, true, false),
                Arguments.of("P2.Cl.Cm", true, false, false),
                Arguments.of("P2.Cl", true, false, false),
                Arguments.of("Cl.Cm", false, false, false),
                Arguments.of("Cl", false, false, false),
                Arguments.of("P2.Cl.Cm", false, false, false),
                Arguments.of("P2.Cl", false, false, false));
    }

    @ParameterizedTest
    @MethodSource("validVectorValues")
    public void shouldReturn200ForSuccessfulTokenRequest(
            String vectorValue,
            boolean clientRegistryConsent,
            boolean expectedConsentRequired,
            boolean clientIdInHeader)
            throws JOSEException {
        KeyPair keyPair = generateRsaKeyPair();
        UserProfile userProfile = generateUserProfile();
        SignedJWT signedJWT =
                generateIDToken(
                        CLIENT_ID,
                        PUBLIC_SUBJECT,
                        "issuer-url",
                        new ECKeyGenerator(Curve.P_256).algorithm(JWSAlgorithm.ES256).generate());
        OIDCTokenResponse tokenResponse =
                new OIDCTokenResponse(new OIDCTokens(signedJWT, accessToken, refreshToken));
        PrivateKeyJWT privateKeyJWT = generatePrivateKeyJWT(keyPair.getPrivate());
        ClientRegistry clientRegistry = generateClientRegistry(keyPair, clientRegistryConsent);

        when(tokenService.validateTokenRequestParams(anyString())).thenReturn(Optional.empty());
        when(clientService.getClient(eq(CLIENT_ID))).thenReturn(Optional.of(clientRegistry));
        when(tokenService.getClientIDFromPrivateKeyJWT(anyString()))
                .thenReturn(Optional.of(CLIENT_ID));
        when(tokenService.validatePrivateKeyJWT(
                        anyString(),
                        eq(clientRegistry.getPublicKey()),
                        eq(BASE_URI),
                        eq(CLIENT_ID)))
                .thenReturn(Optional.empty());
        String authCode = new AuthorizationCode().toString();
        AuthenticationRequest authenticationRequest =
                generateAuthRequest(JsonArrayHelper.jsonArrayOf(vectorValue));
        VectorOfTrust vtr =
                VectorOfTrust.parseFromAuthRequestAttribute(
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
                                                        vtr))));
        when(dynamoService.getUserProfileByEmail(eq(TEST_EMAIL))).thenReturn(userProfile);
        when(tokenService.generateTokenResponse(
                        CLIENT_ID,
                        INTERNAL_SUBJECT,
                        SCOPES,
                        Map.of("nonce", NONCE),
                        PUBLIC_SUBJECT,
                        vtr.retrieveVectorOfTrustForToken(),
                        userProfile.getClientConsent(),
                        expectedConsentRequired,
                        null,
                        false))
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
    public void shouldReturn200ForSuccessfulRefreshTokenRequest(String clientId)
            throws JOSEException, ParseException, Json.JsonException {
        SignedJWT signedRefreshToken = createSignedRefreshToken();
        KeyPair keyPair = generateRsaKeyPair();
        RefreshToken refreshToken = new RefreshToken(signedRefreshToken.serialize());
        OIDCTokenResponse tokenResponse =
                new OIDCTokenResponse(new OIDCTokens(accessToken, refreshToken));
        PrivateKeyJWT privateKeyJWT = generatePrivateKeyJWT(keyPair.getPrivate());
        ClientRegistry clientRegistry = generateClientRegistry(keyPair, false);

        when(tokenService.validateTokenRequestParams(anyString())).thenReturn(Optional.empty());
        when(clientService.getClient(eq(CLIENT_ID))).thenReturn(Optional.of(clientRegistry));
        when(tokenService.getClientIDFromPrivateKeyJWT(anyString()))
                .thenReturn(Optional.of(CLIENT_ID));
        when(tokenService.validatePrivateKeyJWT(
                        anyString(),
                        eq(clientRegistry.getPublicKey()),
                        eq(BASE_URI),
                        eq(CLIENT_ID)))
                .thenReturn(Optional.empty());
        when(tokenValidationService.validateRefreshTokenSignatureAndExpiry(refreshToken))
                .thenReturn(true);
        when(tokenValidationService.validateRefreshTokenScopes(
                        SCOPES.toStringList(), SCOPES.toStringList()))
                .thenReturn(true);
        RefreshTokenStore tokenStore =
                new RefreshTokenStore(refreshToken.getValue(), INTERNAL_SUBJECT.getValue());
        String tokenStoreString = objectMapper.writeValueAsString(tokenStore);
        when(redisConnectionService.popValue(
                        REFRESH_TOKEN_PREFIX + CLIENT_ID + "." + PUBLIC_SUBJECT.getValue()))
                .thenReturn(null);
        String redisKey = REFRESH_TOKEN_PREFIX + signedRefreshToken.getJWTClaimsSet().getJWTID();
        when(redisConnectionService.popValue(redisKey)).thenReturn(tokenStoreString);
        when(tokenService.generateRefreshTokenResponse(
                        eq(CLIENT_ID),
                        eq(INTERNAL_SUBJECT),
                        eq(SCOPES.toStringList()),
                        eq(PUBLIC_SUBJECT)))
                .thenReturn(tokenResponse);

        APIGatewayProxyResponseEvent result =
                generateApiGatewayRefreshRequest(privateKeyJWT, refreshToken.getValue(), clientId);
        assertThat(result, hasStatus(200));
        assertTrue(result.getBody().contains(refreshToken.getValue()));
        assertTrue(result.getBody().contains(accessToken.getValue()));
    }

    @Test
    public void shouldReturn400IfClientIsNotValid() throws JOSEException {
        when(tokenService.validateTokenRequestParams(anyString())).thenReturn(Optional.empty());
        when(clientService.getClient(eq(CLIENT_ID))).thenReturn(Optional.empty());
        KeyPair keyPair = generateRsaKeyPair();
        PrivateKeyJWT privateKeyJWT = generatePrivateKeyJWT(keyPair.getPrivate());
        APIGatewayProxyResponseEvent result =
                generateApiGatewayRequest(
                        privateKeyJWT, new AuthorizationCode().toString(), CLIENT_ID, true);

        assertEquals(400, result.getStatusCode());
        assertThat(result, hasBody(OAuth2Error.INVALID_CLIENT.toJSONObject().toJSONString()));
    }

    @Test
    public void shouldReturn400IfClientIdIsNotValid() {
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
    public void shouldReturn400IfSignatureOfPrivateKeyJWTCantBeVerified() throws JOSEException {
        KeyPair keyPairOne = generateRsaKeyPair();
        KeyPair keyPairTwo = generateRsaKeyPair();
        ClientRegistry clientRegistry = generateClientRegistry(keyPairTwo, false);
        PrivateKeyJWT privateKeyJWT = generatePrivateKeyJWT(keyPairOne.getPrivate());
        when(clientService.getClient(eq(CLIENT_ID))).thenReturn(Optional.of(clientRegistry));
        when(tokenService.validatePrivateKeyJWT(
                        anyString(),
                        eq(clientRegistry.getPublicKey()),
                        eq(TOKEN_URI),
                        eq(CLIENT_ID)))
                .thenReturn(Optional.of(OAuth2Error.INVALID_CLIENT));

        APIGatewayProxyResponseEvent result =
                generateApiGatewayRequest(
                        privateKeyJWT, new AuthorizationCode().toString(), CLIENT_ID, true);

        assertThat(result, hasStatus(400));
        assertThat(result, hasBody(OAuth2Error.INVALID_CLIENT.toJSONObject().toJSONString()));
    }

    @Test
    public void shouldReturn400IfAuthCodeIsNotFound() throws JOSEException {
        KeyPair keyPair = generateRsaKeyPair();
        PrivateKeyJWT privateKeyJWT = generatePrivateKeyJWT(keyPair.getPrivate());
        ClientRegistry clientRegistry = generateClientRegistry(keyPair, false);

        when(tokenService.validateTokenRequestParams(anyString())).thenReturn(Optional.empty());
        when(clientService.getClient(eq(CLIENT_ID))).thenReturn(Optional.of(clientRegistry));
        when(tokenService.getClientIDFromPrivateKeyJWT(anyString()))
                .thenReturn(Optional.of(CLIENT_ID));
        when(tokenService.validatePrivateKeyJWT(
                        anyString(),
                        eq(clientRegistry.getPublicKey()),
                        eq(BASE_URI),
                        eq(CLIENT_ID)))
                .thenReturn(Optional.empty());
        String authCode = new AuthorizationCode().toString();
        when(authorisationCodeService.getExchangeDataForCode(authCode))
                .thenReturn(Optional.empty());

        APIGatewayProxyResponseEvent result =
                generateApiGatewayRequest(privateKeyJWT, authCode, CLIENT_ID, true);
        assertThat(result, hasStatus(400));
        assertThat(result, hasBody(OAuth2Error.INVALID_GRANT.toJSONObject().toJSONString()));
    }

    @Test
    public void shouldReturn400IfRedirectUriDoesNotMatchRedirectUriFromAuthRequest()
            throws JOSEException {
        KeyPair keyPair = generateRsaKeyPair();
        PrivateKeyJWT privateKeyJWT = generatePrivateKeyJWT(keyPair.getPrivate());
        ClientRegistry clientRegistry = generateClientRegistry(keyPair, false);
        when(tokenService.validateTokenRequestParams(anyString())).thenReturn(Optional.empty());
        when(clientService.getClient(eq(CLIENT_ID))).thenReturn(Optional.of(clientRegistry));
        when(tokenService.getClientIDFromPrivateKeyJWT(anyString()))
                .thenReturn(Optional.of(CLIENT_ID));
        when(tokenService.validatePrivateKeyJWT(
                        anyString(),
                        eq(clientRegistry.getPublicKey()),
                        eq(BASE_URI),
                        eq(CLIENT_ID)))
                .thenReturn(Optional.empty());
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
                                                        mock(VectorOfTrust.class)))));

        APIGatewayProxyResponseEvent result =
                generateApiGatewayRequest(
                        privateKeyJWT, authCode, "http://invalid-redirect-uri", CLIENT_ID, true);
        assertThat(result, hasStatus(400));
        assertThat(result, hasBody(OAuth2Error.INVALID_GRANT.toJSONObject().toJSONString()));
    }

    @Test
    void shouldReturn200ForSuccessfulDocAppJourneyTokenRequest() throws JOSEException {
        KeyPair keyPair = generateRsaKeyPair();
        UserProfile userProfile = generateUserProfile();
        SignedJWT signedJWT =
                generateIDToken(
                        DOC_APP_CLIENT_ID.getValue(),
                        PUBLIC_SUBJECT,
                        "issuer-url",
                        new ECKeyGenerator(Curve.P_256).algorithm(JWSAlgorithm.ES256).generate());
        OIDCTokenResponse tokenResponse =
                new OIDCTokenResponse(new OIDCTokens(signedJWT, accessToken, refreshToken));
        PrivateKeyJWT privateKeyJWT = generatePrivateKeyJWT(keyPair.getPrivate());
        ClientRegistry clientRegistry = generateClientRegistry(keyPair, false);

        when(tokenService.validateTokenRequestParams(anyString())).thenReturn(Optional.empty());
        when(clientService.getClient(DOC_APP_CLIENT_ID.getValue()))
                .thenReturn(Optional.of(clientRegistry));
        when(tokenService.getClientIDFromPrivateKeyJWT(anyString()))
                .thenReturn(Optional.of(DOC_APP_CLIENT_ID.getValue()));
        when(tokenService.validatePrivateKeyJWT(
                        anyString(),
                        eq(clientRegistry.getPublicKey()),
                        eq(BASE_URI),
                        eq(DOC_APP_CLIENT_ID.getValue())))
                .thenReturn(Optional.empty());
        String authCode = new AuthorizationCode().toString();
        AuthorizationRequest authenticationRequest = generateRequestObjectAuthRequest();
        VectorOfTrust vtr =
                VectorOfTrust.parseFromAuthRequestAttribute(
                        authenticationRequest.getCustomParameter("vtr"));
        ClientSession clientSession =
                new ClientSession(authenticationRequest.toParameters(), LocalDateTime.now(), vtr);
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
                        vtr.retrieveVectorOfTrustForToken(),
                        null,
                        false,
                        null,
                        true))
                .thenReturn(tokenResponse);

        var result =
                generateApiGatewayRequest(
                        privateKeyJWT, authCode, DOC_APP_CLIENT_ID.getValue(), true);

        assertThat(result, hasStatus(200));
        assertTrue(result.getBody().contains(refreshToken.getValue()));
        assertTrue(result.getBody().contains(accessToken.getValue()));
    }

    private UserProfile generateUserProfile() {
        Set<String> claims = ValidScopes.getClaimsForListOfScopes(SCOPES.toStringList());
        return new UserProfile()
                .setEmail(TEST_EMAIL)
                .setEmailVerified(true)
                .setPhoneNumber(PHONE_NUMBER)
                .setPhoneNumberVerified(true)
                .setSubjectID(INTERNAL_SUBJECT.getValue())
                .setCreated(LocalDateTime.now().toString())
                .setUpdated(LocalDateTime.now().toString())
                .setPublicSubjectID(PUBLIC_SUBJECT.getValue())
                .setClientConsent(
                        new ClientConsent(
                                CLIENT_ID, claims, LocalDateTime.now(ZoneId.of("UTC")).toString()));
    }

    private SignedJWT createSignedRefreshToken() throws JOSEException {
        ECKey ecSigningKey =
                new ECKeyGenerator(Curve.P_256)
                        .keyID("KEY_ID")
                        .algorithm(JWSAlgorithm.ES256)
                        .generate();
        ECDSASigner signer = new ECDSASigner(ecSigningKey);
        return TokenGeneratorHelper.generateSignedToken(
                CLIENT_ID, BASE_URI, SCOPES.toStringList(), signer, PUBLIC_SUBJECT, "KEY_ID");
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

    private ClientRegistry generateClientRegistry(KeyPair keyPair, boolean consentRequired) {
        return new ClientRegistry()
                .setClientID(CLIENT_ID)
                .setConsentRequired(consentRequired)
                .setClientName("test-client")
                .setRedirectUrls(singletonList(REDIRECT_URI))
                .setScopes(SCOPES.toStringList())
                .setContacts(singletonList(TEST_EMAIL))
                .setPublicKey(
                        Base64.getMimeEncoder().encodeToString(keyPair.getPublic().getEncoded()))
                .setSectorIdentifierUri("https://test.com")
                .setSubjectType("public");
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
