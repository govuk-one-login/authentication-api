package uk.gov.di.authentication.oidc.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
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
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.authentication.shared.entity.AuthCodeExchangeData;
import uk.gov.di.authentication.shared.entity.ClientConsent;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.ClientSession;
import uk.gov.di.authentication.shared.entity.RefreshTokenStore;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.entity.ValidScopes;
import uk.gov.di.authentication.shared.entity.VectorOfTrust;
import uk.gov.di.authentication.shared.services.AuthorisationCodeService;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.RedisConnectionService;
import uk.gov.di.authentication.shared.services.TokenService;
import uk.gov.di.authentication.shared.services.TokenValidationService;
import uk.gov.di.authentication.sharedtest.helper.JsonArrayHelper;
import uk.gov.di.authentication.sharedtest.helper.TokenGeneratorHelper;

import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;
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
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.sharedtest.helper.TokenGeneratorHelper.generateIDToken;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

public class TokenHandlerTest {

    private static final String TEST_EMAIL = "joe.bloggs@digital.cabinet-office.gov.uk";
    private static final String PHONE_NUMBER = "01234567890";
    private static final String REDIRECT_URI = "http://localhost/redirect";
    private static final Subject INTERNAL_SUBJECT = new Subject();
    private static final Subject PUBLIC_SUBJECT = new Subject();
    private static final String CLIENT_ID = "test-id";
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

    @BeforeEach
    public void setUp() {
        when(configurationService.getBaseURL()).thenReturn(Optional.of(BASE_URI));
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

    private static Stream<String> validVectorValues() {
        return Stream.of("Cl.Cm", "Cl", "P2.Cl.Cm", "P2.Cl");
    }

    @ParameterizedTest
    @MethodSource("validVectorValues")
    public void shouldReturn200ForSuccessfulTokenRequest(String vectorValue) throws JOSEException {
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
        ClientRegistry clientRegistry = generateClientRegistry(keyPair);

        when(tokenService.validateTokenRequestParams(anyString())).thenReturn(Optional.empty());
        when(clientService.getClient(eq(CLIENT_ID))).thenReturn(Optional.of(clientRegistry));
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
                                        .setClientSessionId(CLIENT_SESSION_ID)));
        AuthenticationRequest authenticationRequest =
                generateAuthRequest(JsonArrayHelper.jsonArrayOf(vectorValue));
        VectorOfTrust vtr =
                VectorOfTrust.parseFromAuthRequestAttribute(
                        authenticationRequest.getCustomParameter("vtr"));
        when(clientSessionService.getClientSession(CLIENT_SESSION_ID))
                .thenReturn(
                        new ClientSession(
                                authenticationRequest.toParameters(), LocalDateTime.now(), vtr));
        when(dynamoService.getUserProfileByEmail(eq(TEST_EMAIL))).thenReturn(userProfile);
        when(tokenService.generateTokenResponse(
                        CLIENT_ID,
                        INTERNAL_SUBJECT,
                        SCOPES,
                        Map.of("nonce", NONCE),
                        PUBLIC_SUBJECT,
                        vtr.retrieveVectorOfTrustForToken(),
                        userProfile.getClientConsent(),
                        clientRegistry.isConsentRequired(),
                        null))
                .thenReturn(tokenResponse);

        APIGatewayProxyResponseEvent result = generateApiGatewayRequest(privateKeyJWT, authCode);
        assertThat(result, hasStatus(200));
        assertTrue(result.getBody().contains(refreshToken.getValue()));
        assertTrue(result.getBody().contains(accessToken.getValue()));
    }

    @Test
    public void shouldReturn200ForSuccessfulRefreshTokenRequest()
            throws JOSEException, JsonProcessingException {
        SignedJWT signedRefreshToken = createSignedRefreshToken();
        KeyPair keyPair = generateRsaKeyPair();
        RefreshToken refreshToken = new RefreshToken(signedRefreshToken.serialize());
        OIDCTokenResponse tokenResponse =
                new OIDCTokenResponse(new OIDCTokens(accessToken, refreshToken));
        PrivateKeyJWT privateKeyJWT = generatePrivateKeyJWT(keyPair.getPrivate());
        ClientRegistry clientRegistry = generateClientRegistry(keyPair);

        when(tokenService.validateTokenRequestParams(anyString())).thenReturn(Optional.empty());
        when(clientService.getClient(eq(CLIENT_ID))).thenReturn(Optional.of(clientRegistry));
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
                new RefreshTokenStore(
                        singletonList(refreshToken.getValue()), INTERNAL_SUBJECT.getValue());
        String redisKey = REFRESH_TOKEN_PREFIX + CLIENT_ID + "." + PUBLIC_SUBJECT.getValue();
        String tokenStoreString = new ObjectMapper().writeValueAsString(tokenStore);
        when(redisConnectionService.getValue(redisKey)).thenReturn(tokenStoreString);
        when(tokenService.generateRefreshTokenResponse(
                        eq(CLIENT_ID),
                        eq(INTERNAL_SUBJECT),
                        eq(SCOPES.toStringList()),
                        eq(PUBLIC_SUBJECT)))
                .thenReturn(tokenResponse);

        APIGatewayProxyResponseEvent result =
                generateApiGatewayRefreshRequest(privateKeyJWT, refreshToken.getValue());
        assertThat(result, hasStatus(200));
        assertTrue(result.getBody().contains(refreshToken.getValue()));
        assertTrue(result.getBody().contains(accessToken.getValue()));
        verify(redisConnectionService, times(1)).deleteValue(redisKey);
    }

    @Test
    public void shouldReturn200ForRefreshTokenRequestWhenMultipleRefreshTokensAreStored()
            throws JOSEException, JsonProcessingException {
        SignedJWT signedRefreshToken = createSignedRefreshToken();
        KeyPair keyPair = generateRsaKeyPair();
        RefreshToken refreshToken = new RefreshToken(signedRefreshToken.serialize());
        RefreshToken refreshToken2 = new RefreshToken();
        OIDCTokenResponse tokenResponse =
                new OIDCTokenResponse(new OIDCTokens(accessToken, refreshToken));
        PrivateKeyJWT privateKeyJWT = generatePrivateKeyJWT(keyPair.getPrivate());
        ClientRegistry clientRegistry = generateClientRegistry(keyPair);

        when(tokenService.validateTokenRequestParams(anyString())).thenReturn(Optional.empty());
        when(clientService.getClient(eq(CLIENT_ID))).thenReturn(Optional.of(clientRegistry));
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
                new RefreshTokenStore(
                        List.of(refreshToken.getValue(), refreshToken2.getValue()),
                        INTERNAL_SUBJECT.getValue());
        String redisKey = REFRESH_TOKEN_PREFIX + CLIENT_ID + "." + PUBLIC_SUBJECT.getValue();
        String tokenStoreString = new ObjectMapper().writeValueAsString(tokenStore);
        when(redisConnectionService.getValue(redisKey)).thenReturn(tokenStoreString);
        when(tokenService.generateRefreshTokenResponse(
                        eq(CLIENT_ID),
                        eq(INTERNAL_SUBJECT),
                        eq(SCOPES.toStringList()),
                        eq(PUBLIC_SUBJECT)))
                .thenReturn(tokenResponse);

        APIGatewayProxyResponseEvent result =
                generateApiGatewayRefreshRequest(privateKeyJWT, refreshToken.getValue());
        assertThat(result, hasStatus(200));
        assertTrue(result.getBody().contains(refreshToken.getValue()));
        assertTrue(result.getBody().contains(accessToken.getValue()));

        String updatedTokenstore =
                new ObjectMapper()
                        .writeValueAsString(
                                new RefreshTokenStore(
                                        List.of(refreshToken2.getValue()),
                                        INTERNAL_SUBJECT.getValue()));
        verify(redisConnectionService, times(1)).saveWithExpiry(redisKey, updatedTokenstore, 1234L);
    }

    @Test
    public void shouldReturn400IfClientIsNotValid() throws JOSEException {
        when(tokenService.validateTokenRequestParams(anyString())).thenReturn(Optional.empty());
        when(clientService.getClient(eq(CLIENT_ID))).thenReturn(Optional.empty());
        KeyPair keyPair = generateRsaKeyPair();
        PrivateKeyJWT privateKeyJWT = generatePrivateKeyJWT(keyPair.getPrivate());
        APIGatewayProxyResponseEvent result =
                generateApiGatewayRequest(privateKeyJWT, new AuthorizationCode().toString());

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
        ClientRegistry clientRegistry = generateClientRegistry(keyPairTwo);
        PrivateKeyJWT privateKeyJWT = generatePrivateKeyJWT(keyPairOne.getPrivate());
        when(clientService.getClient(eq(CLIENT_ID))).thenReturn(Optional.of(clientRegistry));
        when(tokenService.validatePrivateKeyJWT(
                        anyString(),
                        eq(clientRegistry.getPublicKey()),
                        eq(TOKEN_URI),
                        eq(CLIENT_ID)))
                .thenReturn(Optional.of(OAuth2Error.INVALID_CLIENT));

        APIGatewayProxyResponseEvent result =
                generateApiGatewayRequest(privateKeyJWT, new AuthorizationCode().toString());

        assertThat(result, hasStatus(400));
        assertThat(result, hasBody(OAuth2Error.INVALID_CLIENT.toJSONObject().toJSONString()));
    }

    @Test
    public void shouldReturn400IfAuthCodeIsNotFound() throws JOSEException {
        KeyPair keyPair = generateRsaKeyPair();
        PrivateKeyJWT privateKeyJWT = generatePrivateKeyJWT(keyPair.getPrivate());
        ClientRegistry clientRegistry = generateClientRegistry(keyPair);

        when(tokenService.validateTokenRequestParams(anyString())).thenReturn(Optional.empty());
        when(clientService.getClient(eq(CLIENT_ID))).thenReturn(Optional.of(clientRegistry));
        when(tokenService.validatePrivateKeyJWT(
                        anyString(),
                        eq(clientRegistry.getPublicKey()),
                        eq(BASE_URI),
                        eq(CLIENT_ID)))
                .thenReturn(Optional.empty());
        String authCode = new AuthorizationCode().toString();
        when(authorisationCodeService.getExchangeDataForCode(authCode))
                .thenReturn(Optional.empty());

        APIGatewayProxyResponseEvent result = generateApiGatewayRequest(privateKeyJWT, authCode);
        assertThat(result, hasStatus(400));
        assertThat(result, hasBody(OAuth2Error.INVALID_GRANT.toJSONObject().toJSONString()));
    }

    @Test
    public void shouldReturn400IfRedirectUriDoesNotMatchRedirectUriFromAuthRequest()
            throws JOSEException {
        KeyPair keyPair = generateRsaKeyPair();
        PrivateKeyJWT privateKeyJWT = generatePrivateKeyJWT(keyPair.getPrivate());
        ClientRegistry clientRegistry = generateClientRegistry(keyPair);

        when(tokenService.validateTokenRequestParams(anyString())).thenReturn(Optional.empty());
        when(clientService.getClient(eq(CLIENT_ID))).thenReturn(Optional.of(clientRegistry));
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
                                        .setClientSessionId(CLIENT_SESSION_ID)));
        when(clientSessionService.getClientSession(CLIENT_SESSION_ID))
                .thenReturn(
                        new ClientSession(
                                generateAuthRequest().toParameters(),
                                LocalDateTime.now(),
                                mock(VectorOfTrust.class)));

        APIGatewayProxyResponseEvent result =
                generateApiGatewayRequest(privateKeyJWT, authCode, "http://invalid-redirect-uri");
        assertThat(result, hasStatus(400));
        assertThat(result, hasBody(OAuth2Error.INVALID_GRANT.toJSONObject().toJSONString()));
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
                (RSAPrivateKey) privateKey,
                null,
                null);
    }

    private ClientRegistry generateClientRegistry(KeyPair keyPair) {
        return new ClientRegistry()
                .setClientID(CLIENT_ID)
                .setConsentRequired(false)
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
            PrivateKeyJWT privateKeyJWT, String authorisationCode, String redirectUri) {
        Map<String, List<String>> customParams = new HashMap<>();
        customParams.put(
                "grant_type", Collections.singletonList(GrantType.AUTHORIZATION_CODE.getValue()));
        customParams.put("client_id", Collections.singletonList(CLIENT_ID));
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
            PrivateKeyJWT privateKeyJWT, String refreshToken) {
        Map<String, List<String>> customParams = new HashMap<>();
        customParams.put(
                "grant_type", Collections.singletonList(GrantType.REFRESH_TOKEN.getValue()));
        customParams.put("client_id", Collections.singletonList(CLIENT_ID));
        customParams.put("refresh_token", Collections.singletonList(refreshToken));
        Map<String, List<String>> privateKeyParams = privateKeyJWT.toParameters();
        privateKeyParams.putAll(customParams);
        String requestParams = URLUtils.serializeParameters(privateKeyParams);
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody(requestParams);
        return handler.handleRequest(event, context);
    }

    private APIGatewayProxyResponseEvent generateApiGatewayRequest(
            PrivateKeyJWT privateKeyJWT, String authorisationCode) {
        return generateApiGatewayRequest(privateKeyJWT, authorisationCode, REDIRECT_URI);
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
}
