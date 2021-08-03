package uk.gov.di.lambdas;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.auth.PrivateKeyJWT;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.util.URLUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.entity.AuthCodeExchangeData;
import uk.gov.di.entity.ClientRegistry;
import uk.gov.di.entity.ClientSession;
import uk.gov.di.entity.ErrorResponse;
import uk.gov.di.helpers.ObjectMapperFactory;
import uk.gov.di.services.AuthenticationService;
import uk.gov.di.services.AuthorisationCodeService;
import uk.gov.di.services.ClientService;
import uk.gov.di.services.ClientSessionService;
import uk.gov.di.services.ConfigurationService;
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

import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.matchers.APIGatewayProxyResponseEventMatcher.hasBody;
import static uk.gov.di.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

public class TokenHandlerTest {

    private static final String TEST_EMAIL = "joe.bloggs@digital.cabinet-office.gov.uk";
    private static final Subject TEST_SUBJECT = new Subject();
    private static final String CLIENT_ID = "test-id";
    private static final List<String> SCOPES = List.of("openid");
    private static final String ENDPOINT_URI = "http://localhost/token";
    public static final String CLIENT_SESSION_ID = "a-client-session-id";
    private final Context context = mock(Context.class);
    private final SignedJWT signedJWT = mock(SignedJWT.class);
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
    public void shouldReturn200IfSuccessfulRequest() throws JOSEException {
        KeyPair keyPair = generateRsaKeyPair();
        PrivateKeyJWT privateKeyJWT = generatePrivateKeyJWT(CLIENT_ID, keyPair.getPrivate());
        ClientRegistry clientRegistry =
                new ClientRegistry()
                        .setClientID(CLIENT_ID)
                        .setClientName("test-client")
                        .setRedirectUrls(singletonList("http://localhost/redirect"))
                        .setScopes(singletonList("openid"))
                        .setContacts(singletonList(TEST_EMAIL))
                        .setPublicKey(
                                Base64.getMimeEncoder()
                                        .encodeToString(keyPair.getPublic().getEncoded()));
        BearerAccessToken accessToken = new BearerAccessToken();
        when(configurationService.getBaseURL()).thenReturn(Optional.of(ENDPOINT_URI));
        when(clientService.getClient(eq(CLIENT_ID))).thenReturn(Optional.of(clientRegistry));
        when(tokenService.validatePrivateKeyJWTSignature(
                        eq(clientRegistry.getPublicKey()),
                        any(PrivateKeyJWT.class),
                        eq(ENDPOINT_URI)))
                .thenReturn(true);
        when(authenticationService.getSubjectFromEmail(eq(TEST_EMAIL))).thenReturn(TEST_SUBJECT);
        when(tokenService.generateAndStoreAccessToken(eq(CLIENT_ID), eq(TEST_SUBJECT), eq(SCOPES)))
                .thenReturn(accessToken);
        when(tokenService.generateIDToken(eq(CLIENT_ID), any(Subject.class))).thenReturn(signedJWT);
        String authCode = new AuthorizationCode().toString();
        when(authorisationCodeService.getExchangeDataForCode(authCode))
                .thenReturn(
                        Optional.of(
                                new AuthCodeExchangeData()
                                        .setClientSessionId(CLIENT_SESSION_ID)
                                        .setEmail(TEST_EMAIL)));
        when(clientSessionService.getClientSession(CLIENT_SESSION_ID))
                .thenReturn(
                        new ClientSession(
                                generateAuthRequest().toParameters(), LocalDateTime.now()));

        APIGatewayProxyResponseEvent result =
                generateApiGatewayRequest(privateKeyJWT, CLIENT_ID, authCode);

        assertThat(result, hasStatus(200));
        assertTrue(result.getBody().contains(accessToken.getValue()));
    }

    @Test
    public void shouldReturn403IfClientIsNotValid() throws JOSEException, JsonProcessingException {
        String invalidClientID = "invalid-id";
        when(clientService.getClient(eq(invalidClientID))).thenReturn(Optional.empty());
        KeyPair keyPair = generateRsaKeyPair();
        PrivateKeyJWT privateKeyJWT = generatePrivateKeyJWT(invalidClientID, keyPair.getPrivate());

        APIGatewayProxyResponseEvent result =
                generateApiGatewayRequest(privateKeyJWT, invalidClientID);

        assertEquals(403, result.getStatusCode());
        String expectedResponse =
                ObjectMapperFactory.getInstance().writeValueAsString(ErrorResponse.ERROR_1016);
        assertThat(result, hasBody(expectedResponse));
    }

    @Test
    public void shouldReturn400IfAnyRequestParametersAreMissing() throws JsonProcessingException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody("code=343242");

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertEquals(400, result.getStatusCode());
        String expectedResponse =
                ObjectMapperFactory.getInstance().writeValueAsString(ErrorResponse.ERROR_1001);
        assertThat(result, hasBody(expectedResponse));
    }

    @Test
    public void shouldReturn403IfSignatureOfPrivateKeyJWTCantBeVerified()
            throws JOSEException, JsonProcessingException {
        KeyPair keyPairOne = generateRsaKeyPair();
        KeyPair keyPairTwo = generateRsaKeyPair();
        ClientRegistry clientRegistry =
                new ClientRegistry()
                        .setClientID(CLIENT_ID)
                        .setClientName("test-client")
                        .setRedirectUrls(singletonList("http://localhost/redirect"))
                        .setScopes(singletonList("openid"))
                        .setContacts(singletonList(TEST_EMAIL))
                        .setPublicKey(
                                Base64.getMimeEncoder()
                                        .encodeToString(keyPairTwo.getPublic().getEncoded()));
        PrivateKeyJWT privateKeyJWT = generatePrivateKeyJWT(CLIENT_ID, keyPairOne.getPrivate());
        when(configurationService.getBaseURL()).thenReturn(Optional.of(ENDPOINT_URI));
        when(clientService.getClient(eq(CLIENT_ID))).thenReturn(Optional.of(clientRegistry));
        when(tokenService.validatePrivateKeyJWTSignature(
                        eq(clientRegistry.getPublicKey()),
                        any(PrivateKeyJWT.class),
                        eq(ENDPOINT_URI)))
                .thenReturn(false);

        APIGatewayProxyResponseEvent result = generateApiGatewayRequest(privateKeyJWT, CLIENT_ID);

        assertThat(result, hasStatus(403));
        String expectedResponse =
                ObjectMapperFactory.getInstance().writeValueAsString(ErrorResponse.ERROR_1015);
        assertThat(result, hasBody(expectedResponse));
    }

    private PrivateKeyJWT generatePrivateKeyJWT(String clientID, PrivateKey privateKey)
            throws JOSEException {
        return new PrivateKeyJWT(
                new ClientID(clientID),
                URI.create(ENDPOINT_URI),
                JWSAlgorithm.RS256,
                (RSAPrivateKey) privateKey,
                null,
                null);
    }

    private APIGatewayProxyResponseEvent generateApiGatewayRequest(
            PrivateKeyJWT privateKeyJWT, String clientID) {
        return generateApiGatewayRequest(
                privateKeyJWT, clientID, new AuthorizationCode().toString());
    }

    private APIGatewayProxyResponseEvent generateApiGatewayRequest(
            PrivateKeyJWT privateKeyJWT, String clientID, String authorisationCode) {
        Map<String, List<String>> customParams = new HashMap<>();
        customParams.put("grant_type", Collections.singletonList("authorization_code"));
        customParams.put("client_id", Collections.singletonList(clientID));
        customParams.put("code", Collections.singletonList(authorisationCode));
        customParams.put("redirect_uri", Collections.singletonList("http://localhost/redirect"));
        Map<String, List<String>> privateKeyParams = privateKeyJWT.toParameters();
        privateKeyParams.putAll(customParams);
        String requestParams = URLUtils.serializeParameters(privateKeyParams);
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody(requestParams);
        return handler.handleRequest(event, context);
    }

    private AuthorizationRequest generateAuthRequest() {
        Scope scopeValues = new Scope();
        scopeValues.add("openid");
        ResponseType responseType = new ResponseType(ResponseType.Value.CODE);
        State state = new State();
        return new AuthorizationRequest.Builder(responseType, new ClientID(CLIENT_ID))
                .redirectionURI(URI.create("http://localhost:8080/redirect"))
                .state(state)
                .scope(scopeValues)
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
