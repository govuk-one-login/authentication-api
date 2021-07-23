package uk.gov.di.lambdas;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.entity.ClientSession;
import uk.gov.di.entity.ErrorResponse;
import uk.gov.di.entity.Session;
import uk.gov.di.exceptions.ClientNotFoundException;
import uk.gov.di.services.AuthorizationService;
import uk.gov.di.services.CodeStorageService;
import uk.gov.di.services.ConfigurationService;
import uk.gov.di.services.SessionService;

import java.net.URI;
import java.time.LocalDateTime;
import java.util.Map;
import java.util.Optional;

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.matchers.APIGatewayProxyResponseEventMatcher.hasBody;
import static uk.gov.di.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class AuthCodeHandlerTest {

    private static final String SESSION_ID = "a-session-id";
    private static final String CLIENT_SESSION_ID = "client-session-id";
    private static final URI REDIRECT_URI = URI.create("http://localhost/redirect");
    private final AuthorizationService authorizationService = mock(AuthorizationService.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final CodeStorageService codeStorageService = mock(CodeStorageService.class);
    private final SessionService sessionService = mock(SessionService.class);
    private final Context context = mock(Context.class);
    private AuthCodeHandler handler;

    @BeforeEach
    public void setUp() {
        handler =
                new AuthCodeHandler(
                        sessionService,
                        codeStorageService,
                        configurationService,
                        authorizationService);
    }

    @Test
    public void shouldGenerateSuccessfulAuthResponse() throws ClientNotFoundException {
        ClientID clientID = new ClientID();
        AuthorizationRequest authRequest =
                generateValidSessionAndAuthRequest(clientID, REDIRECT_URI);

        AuthenticationSuccessResponse authSuccessResponse =
                new AuthenticationSuccessResponse(
                        authRequest.getRedirectionURI(),
                        new AuthorizationCode(),
                        null,
                        null,
                        authRequest.getState(),
                        null,
                        null);

        when(authorizationService.isClientRedirectUriValid(eq(clientID), eq(REDIRECT_URI)))
                .thenReturn(true);
        when(configurationService.getAuthCodeExpiry()).thenReturn(300L);
        when(authorizationService.generateSuccessfulAuthResponse(
                        any(AuthorizationRequest.class), any(AuthorizationCode.class)))
                .thenReturn(authSuccessResponse);
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("Session-Id", SESSION_ID));
        event.setBody(format("{ \"client_session_id\": \"%s\"}", CLIENT_SESSION_ID));
        APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);

        verify(codeStorageService)
                .saveAuthorizationCode(anyString(), eq(CLIENT_SESSION_ID), eq(300L));
        assertThat(response, hasStatus(302));
        assertThat(
                response.getHeaders().get("Location"),
                equalTo(authSuccessResponse.toURI().toString()));
    }

    @Test
    public void shouldGenerateErrorResponseWhenSessionIsNotFound() throws JsonProcessingException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody(format("{ \"client_session_id\": \"%s\"}", CLIENT_SESSION_ID));
        APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);

        assertThat(response, hasStatus(400));
        String expectedResponse = new ObjectMapper().writeValueAsString(ErrorResponse.ERROR_1000);
        assertThat(response, hasBody(expectedResponse));
    }

    @Test
    public void shouldGenerateErrorResponseWhenRedirectUriIsInvalid()
            throws ClientNotFoundException, JsonProcessingException {
        ClientID clientID = new ClientID();
        generateValidSessionAndAuthRequest(clientID, REDIRECT_URI);
        when(authorizationService.isClientRedirectUriValid(eq(new ClientID()), eq(REDIRECT_URI)))
                .thenReturn(false);
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("Session-Id", SESSION_ID));
        event.setBody(format("{ \"client_session_id\": \"%s\"}", CLIENT_SESSION_ID));
        APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);

        assertThat(response, hasStatus(400));
        String expectedResponse = new ObjectMapper().writeValueAsString(ErrorResponse.ERROR_1017);
        assertThat(response, hasBody(expectedResponse));
    }

    @Test
    public void shouldGenerateErrorResponseWhenClientIsNotFound()
            throws ClientNotFoundException, JsonProcessingException {
        ClientID clientID = new ClientID();
        generateValidSessionAndAuthRequest(clientID, REDIRECT_URI);
        doThrow(ClientNotFoundException.class)
                .when(authorizationService)
                .isClientRedirectUriValid(eq(clientID), eq(REDIRECT_URI));

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("Session-Id", SESSION_ID));
        event.setBody(format("{ \"client_session_id\": \"%s\"}", CLIENT_SESSION_ID));
        APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);

        assertThat(response, hasStatus(400));
        String expectedResponse = new ObjectMapper().writeValueAsString(ErrorResponse.ERROR_1016);
        assertThat(response, hasBody(expectedResponse));
    }

    @Test
    public void shouldGenerateErrorResponseIfRequestParametersAreMissing()
            throws JsonProcessingException {
        ClientID clientID = new ClientID();
        generateValidSessionAndAuthRequest(clientID, REDIRECT_URI);
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("Session-Id", SESSION_ID));
        event.setBody("{ }");
        APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);

        assertThat(response, hasStatus(400));
        String expectedResponse = new ObjectMapper().writeValueAsString(ErrorResponse.ERROR_1001);
        assertThat(response, hasBody(expectedResponse));
    }

    private AuthorizationRequest generateValidSessionAndAuthRequest(
            ClientID clientID, URI redirectURI) {
        ResponseType responseType = new ResponseType(ResponseType.Value.CODE);
        State state = new State();
        AuthorizationRequest authorizationRequest =
                new AuthorizationRequest.Builder(responseType, clientID)
                        .redirectionURI(redirectURI)
                        .state(state)
                        .build();
        when(sessionService.getSessionFromRequestHeaders(anyMap()))
                .thenReturn(
                        Optional.of(
                                new Session(SESSION_ID, CLIENT_SESSION_ID)
                                        .setClientSession(
                                                CLIENT_SESSION_ID,
                                                new ClientSession(
                                                        authorizationRequest.toParameters(),
                                                        LocalDateTime.now()))));
        return authorizationRequest;
    }
}
