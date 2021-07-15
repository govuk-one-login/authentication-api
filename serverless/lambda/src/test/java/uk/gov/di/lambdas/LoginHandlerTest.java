package uk.gov.di.lambdas;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.entity.ErrorResponse;
import uk.gov.di.entity.LoginResponse;
import uk.gov.di.entity.Session;
import uk.gov.di.helpers.RedactPhoneNumberHelper;
import uk.gov.di.services.AuthenticationService;
import uk.gov.di.services.SessionService;

import java.util.Map;
import java.util.Optional;

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.entity.SessionState.AUTHENTICATED;
import static uk.gov.di.matchers.APIGatewayProxyResponseEventMatcher.hasBody;
import static uk.gov.di.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class LoginHandlerTest {

    private static final String EMAIL = "computer-1";
    private static final String PASSWORD = "joe.bloggs@test.com";
    private static final String PHONE_NUMBER = "01234567890";
    private LoginHandler handler;
    private final Context context = mock(Context.class);
    private final AuthenticationService authenticationService = mock(AuthenticationService.class);
    private final SessionService sessionService = mock(SessionService.class);

    @BeforeEach
    public void setUp() {
        handler = new LoginHandler(sessionService, authenticationService);
    }

    @Test
    public void shouldReturn200IfLoginIsSuccessful() throws JsonProcessingException {
        when(authenticationService.userExists(EMAIL)).thenReturn(true);
        when(authenticationService.login(EMAIL, PASSWORD)).thenReturn(true);
        when(authenticationService.getPhoneNumber(EMAIL)).thenReturn(Optional.of(PHONE_NUMBER));
        usingValidSession();
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("Session-Id", "a-session-id"));
        event.setBody(format("{ \"password\": \"%s\", \"email\": \"%s\" }", PASSWORD, EMAIL));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(200));

        LoginResponse response =
                new ObjectMapper().readValue(result.getBody(), LoginResponse.class);
        assertThat(response.getSessionState(), equalTo(AUTHENTICATED));
        assertThat(
                response.getRedactedPhoneNumber(),
                equalTo(RedactPhoneNumberHelper.redactPhoneNumber(PHONE_NUMBER)));
    }

    @Test
    public void shouldReturn401IfUserHasInvalidCredentials() throws JsonProcessingException {
        when(authenticationService.userExists(EMAIL)).thenReturn(true);
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("Session-Id", "a-session-id"));
        event.setBody(format("{ \"password\": \"%s\", \"email\": \"%s\" }", PASSWORD, EMAIL));
        when(authenticationService.login(EMAIL, PASSWORD)).thenReturn(false);
        usingValidSession();

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(401));
        String expectedResponse = new ObjectMapper().writeValueAsString(ErrorResponse.ERROR_1008);
        assertThat(result, hasBody(expectedResponse));
    }

    @Test
    public void shouldReturn400IfAnyRequestParametersAreMissing() throws JsonProcessingException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("Session-Id", "a-session-id"));
        event.setBody(format("{ \"password\": \"%s\"}", PASSWORD));

        when(authenticationService.login(EMAIL, PASSWORD)).thenReturn(false);
        usingValidSession();
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        String expectedResponse = new ObjectMapper().writeValueAsString(ErrorResponse.ERROR_1001);
        assertThat(result, hasBody(expectedResponse));
    }

    @Test
    public void shouldReturn400IfSessionIdIsInvalid() throws JsonProcessingException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("Session-Id", "a-session-id"));
        event.setBody(format("{ \"password\": \"%s\"}", PASSWORD));

        when(authenticationService.login(EMAIL, PASSWORD)).thenReturn(false);
        when(sessionService.getSessionFromRequestHeaders(event.getHeaders()))
                .thenReturn(Optional.empty());

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        String expectedResponse = new ObjectMapper().writeValueAsString(ErrorResponse.ERROR_1000);
        assertThat(result, hasBody(expectedResponse));
    }

    @Test
    public void shouldReturn400IfUserDoesNotHaveAnAccount() throws JsonProcessingException {
        when(authenticationService.userExists(EMAIL)).thenReturn(false);
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("Session-Id", "a-session-id"));
        event.setBody(format("{ \"password\": \"%s\", \"email\": \"%s\" }", PASSWORD, EMAIL));
        when(authenticationService.login(EMAIL, PASSWORD)).thenReturn(false);
        usingValidSession();

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        String expectedResponse = new ObjectMapper().writeValueAsString(ErrorResponse.ERROR_1010);
        assertThat(result, hasBody(expectedResponse));
    }

    private void usingValidSession() {
        when(sessionService.getSessionFromRequestHeaders(anyMap()))
                .thenReturn(Optional.of(new Session("a-session-id", "client-session-id")));
    }
}
