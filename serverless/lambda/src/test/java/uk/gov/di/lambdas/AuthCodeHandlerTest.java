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
import uk.gov.di.services.AuthorisationCodeService;
import uk.gov.di.services.AuthorizationService;
import uk.gov.di.services.ClientSessionService;
import uk.gov.di.services.ConfigurationService;
import uk.gov.di.services.SessionService;

import java.net.URI;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.matchers.APIGatewayProxyResponseEventMatcher.hasBody;
import static uk.gov.di.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class AuthCodeHandlerTest {

    private static final String SESSION_ID = "a-session-id";
    private static final String CLIENT_SESSION_ID = "client-session-id";
    private static final String COOKIE = "cookie";
    private static final String EMAIL = "joe.bloggs@digital.cabinet-office.gov.uk";
    private static final URI REDIRECT_URI = URI.create("http://localhost/redirect");
    private final AuthorizationService authorizationService = mock(AuthorizationService.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final AuthorisationCodeService authorisationCodeService =
            mock(AuthorisationCodeService.class);
    private final SessionService sessionService = mock(SessionService.class);
    private final Context context = mock(Context.class);
    private final ClientSessionService clientSessionService = mock(ClientSessionService.class);
    private AuthCodeHandler handler;

    @BeforeEach
    public void setUp() {
        handler =
                new AuthCodeHandler(
                        sessionService,
                        authorisationCodeService,
                        configurationService,
                        authorizationService,
                        clientSessionService);
    }

    @Test
    public void shouldGenerateSuccessfulAuthResponse() throws ClientNotFoundException {
        ClientID clientID = new ClientID();
        AuthorizationCode authorizationCode = new AuthorizationCode();
        AuthorizationRequest authRequest = generateValidSessionAndAuthRequest(clientID);
        AuthenticationSuccessResponse authSuccessResponse =
                new AuthenticationSuccessResponse(
                        authRequest.getRedirectionURI(),
                        authorizationCode,
                        null,
                        null,
                        authRequest.getState(),
                        null,
                        null);

        when(authorizationService.isClientRedirectUriValid(eq(clientID), eq(REDIRECT_URI)))
                .thenReturn(true);
        when(authorisationCodeService.generateAuthorisationCode(eq(CLIENT_SESSION_ID)))
                .thenReturn(authorizationCode);
        when(authorizationService.generateSuccessfulAuthResponse(
                        any(AuthorizationRequest.class), any(AuthorizationCode.class)))
                .thenReturn(authSuccessResponse);

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of(COOKIE, buildCookieString()));
        APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);

        assertThat(response, hasStatus(302));
        assertThat(
                response.getHeaders().get("Location"),
                equalTo(authSuccessResponse.toURI().toString()));
    }

    @Test
    public void shouldGenerateErrorResponseWhenSessionIsNotFound() throws JsonProcessingException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of(COOKIE, buildCookieString()));
        APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);

        assertThat(response, hasStatus(400));
        String expectedResponse = new ObjectMapper().writeValueAsString(ErrorResponse.ERROR_1000);
        assertThat(response, hasBody(expectedResponse));
    }

    @Test
    public void shouldGenerateErrorResponseWhenRedirectUriIsInvalid()
            throws ClientNotFoundException, JsonProcessingException {
        ClientID clientID = new ClientID();
        generateValidSessionAndAuthRequest(clientID);
        when(authorizationService.isClientRedirectUriValid(eq(new ClientID()), eq(REDIRECT_URI)))
                .thenReturn(false);
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of(COOKIE, buildCookieString()));
        APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);

        assertThat(response, hasStatus(400));
        String expectedResponse = new ObjectMapper().writeValueAsString(ErrorResponse.ERROR_1017);
        assertThat(response, hasBody(expectedResponse));
    }

    @Test
    public void shouldGenerateErrorResponseWhenClientIsNotFound()
            throws ClientNotFoundException, JsonProcessingException {
        ClientID clientID = new ClientID();
        generateValidSessionAndAuthRequest(clientID);
        doThrow(ClientNotFoundException.class)
                .when(authorizationService)
                .isClientRedirectUriValid(eq(clientID), eq(REDIRECT_URI));

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of(COOKIE, buildCookieString()));
        APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);

        assertThat(response, hasStatus(400));
        String expectedResponse = new ObjectMapper().writeValueAsString(ErrorResponse.ERROR_1016);
        assertThat(response, hasBody(expectedResponse));
    }

    @Test
    public void shouldGenerateErrorResponseIfUnableToParseAuthRequest()
            throws JsonProcessingException {
        generateValidSession(Map.of("rubbish", List.of("more-rubbish")));
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of(COOKIE, buildCookieString()));
        APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);

        assertThat(response, hasStatus(400));
        String expectedResponse = new ObjectMapper().writeValueAsString(ErrorResponse.ERROR_1001);
        assertThat(response, hasBody(expectedResponse));
    }

    private AuthorizationRequest generateValidSessionAndAuthRequest(ClientID clientID) {
        ResponseType responseType = new ResponseType(ResponseType.Value.CODE);
        State state = new State();
        AuthorizationRequest authorizationRequest =
                new AuthorizationRequest.Builder(responseType, clientID)
                        .redirectionURI(REDIRECT_URI)
                        .state(state)
                        .build();
        generateValidSession(authorizationRequest.toParameters());
        return authorizationRequest;
    }

    private void generateValidSession(Map<String, List<String>> authRequest) {
        when(sessionService.readSessionFromRedis(SESSION_ID))
                .thenReturn(
                        Optional.of(new Session(SESSION_ID).addClientSession(CLIENT_SESSION_ID)));
        when(clientSessionService.getClientSession(CLIENT_SESSION_ID))
                .thenReturn(new ClientSession(authRequest, LocalDateTime.now(), EMAIL));
    }

    private String buildCookieString() {
        return format(
                "%s=%s.%s; Max-Age=%d; %s",
                "gs", SESSION_ID, CLIENT_SESSION_ID, 1800, "Secure; HttpOnly;");
    }
}
