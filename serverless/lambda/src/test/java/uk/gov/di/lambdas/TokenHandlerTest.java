package uk.gov.di.lambdas;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.auth.PrivateKeyJWT;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.util.URLUtils;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.entity.AuthCodeExchangeData;
import uk.gov.di.entity.ClientRegistry;
import uk.gov.di.entity.ClientSession;
import uk.gov.di.services.AuthenticationService;
import uk.gov.di.services.AuthorisationCodeService;
import uk.gov.di.services.ClientService;
import uk.gov.di.services.ClientSessionService;
import uk.gov.di.services.TokenService;

import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.helpers.TokenGeneratorHelper.generateIDToken;
import static uk.gov.di.matchers.APIGatewayProxyResponseEventMatcher.hasBody;
import static uk.gov.di.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

public class TokenHandlerTest {

    private static final String TEST_EMAIL = "joe.bloggs@digital.cabinet-office.gov.uk";
    private static final String REDIRECT_URI = "http://localhost/redirect";
    private static final Subject TEST_SUBJECT = new Subject();
    private static final String CLIENT_ID = "test-id";
    private static final List<String> SCOPES = List.of("openid");
    private static final String BASE_URI = "http://localhost";
    private static final String TOKEN_URI = "http://localhost/token";
    public static final String CLIENT_SESSION_ID = "a-client-session-id";
    private final Context context = mock(Context.class);
    private final AuthenticationService authenticationService = mock(AuthenticationService.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final TokenService tokenService = mock(TokenService.class);
    private final ClientService clientService = mock(ClientService.class);
    private final AuthorisationCodeService authorisationCodeService =
            mock(AuthorisationCodeService.class);
    private final ClientSessionService clientSessionService = mock(ClientSessionService.class);
    private TokenHandler handler;

    @BeforeEach
    public void setUp() {
        when(configurationService.getBaseURL()).thenReturn(Optional.of(BASE_URI));
        handler =
                new TokenHandler(
                        clientService,
                        tokenService,
                        authenticationService,
                        configurationService,
                        authorisationCodeService,
                        clientSessionService);
    }

    @Test
    public void shouldReturn200ForSuccessfulTokenRequest() throws JOSEException {
        KeyPair keyPair = generateRsaKeyPair();
        SignedJWT signedJWT =
                generateIDToken(
                        CLIENT_ID,
                        TEST_SUBJECT,
                        "issuer-url",
                        new RSAKeyGenerator(2048).keyID(UUID.randomUUID().toString()).generate());
        BearerAccessToken accessToken = new BearerAccessToken();
        OIDCTokenResponse tokenResponse =
                new OIDCTokenResponse(new OIDCTokens(signedJWT, accessToken, null));
        PrivateKeyJWT privateKeyJWT = generatePrivateKeyJWT(keyPair.getPrivate());
        ClientRegistry clientRegistry = generateClientRegistry(keyPair);

        when(tokenService.validateTokenRequestParams(anyString())).thenReturn(Optional.empty());
        when(clientService.getClient(eq(CLIENT_ID))).thenReturn(Optional.of(clientRegistry));
        when(tokenService.validatePrivateKeyJWT(
                        anyString(), eq(clientRegistry.getPublicKey()), eq(BASE_URI)))
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
                                generateAuthRequest().toParameters(), LocalDateTime.now()));
        when(authenticationService.getSubjectFromEmail(eq(TEST_EMAIL))).thenReturn(TEST_SUBJECT);
        when(tokenService.generateTokenResponse(eq(CLIENT_ID), any(Subject.class), eq(SCOPES)))
                .thenReturn(tokenResponse);

        APIGatewayProxyResponseEvent result = generateApiGatewayRequest(privateKeyJWT, authCode);
        assertThat(result, hasStatus(200));
        assertTrue(result.getBody().contains(accessToken.getValue()));
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
                        anyString(), eq(clientRegistry.getPublicKey()), eq(TOKEN_URI)))
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
                        anyString(), eq(clientRegistry.getPublicKey()), eq(BASE_URI)))
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
                        anyString(), eq(clientRegistry.getPublicKey()), eq(BASE_URI)))
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
                                generateAuthRequest().toParameters(), LocalDateTime.now()));

        APIGatewayProxyResponseEvent result =
                generateApiGatewayRequest(privateKeyJWT, authCode, "http://invalid-redirect-uri");
        assertThat(result, hasStatus(400));
        assertThat(result, hasBody(OAuth2Error.INVALID_GRANT.toJSONObject().toJSONString()));
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
                .setClientName("test-client")
                .setRedirectUrls(singletonList(REDIRECT_URI))
                .setScopes(singletonList("openid"))
                .setContacts(singletonList(TEST_EMAIL))
                .setPublicKey(
                        Base64.getMimeEncoder().encodeToString(keyPair.getPublic().getEncoded()));
    }

    private APIGatewayProxyResponseEvent generateApiGatewayRequest(
            PrivateKeyJWT privateKeyJWT, String authorisationCode, String redirectUri) {
        Map<String, List<String>> customParams = new HashMap<>();
        customParams.put("grant_type", Collections.singletonList("authorization_code"));
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

    private APIGatewayProxyResponseEvent generateApiGatewayRequest(
            PrivateKeyJWT privateKeyJWT, String authorisationCode) {
        return generateApiGatewayRequest(privateKeyJWT, authorisationCode, REDIRECT_URI);
    }

    private AuthenticationRequest generateAuthRequest() {
        ResponseType responseType = new ResponseType(ResponseType.Value.CODE);
        State state = new State();
        return new AuthenticationRequest.Builder(
                        responseType,
                        Scope.parse(SCOPES),
                        new ClientID(CLIENT_ID),
                        URI.create(REDIRECT_URI))
                .state(state)
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
