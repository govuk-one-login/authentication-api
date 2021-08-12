package uk.gov.di.lambdas;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.entity.BaseAPIResponse;
import uk.gov.di.entity.ErrorResponse;
import uk.gov.di.entity.Session;
import uk.gov.di.entity.SessionState;
import uk.gov.di.helpers.IdGenerator;
import uk.gov.di.services.AuthenticationService;
import uk.gov.di.services.SessionService;
import uk.gov.di.services.ValidationService;

import java.util.Map;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.entity.SessionState.EMAIL_CODE_VERIFIED;
import static uk.gov.di.entity.SessionState.NEW;
import static uk.gov.di.entity.SessionState.TWO_FACTOR_REQUIRED;
import static uk.gov.di.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class SignUpHandlerTest {

    private final Context context = mock(Context.class);
    private final AuthenticationService authenticationService = mock(AuthenticationService.class);
    private final ValidationService validationService = mock(ValidationService.class);
    private final SessionService sessionService = mock(SessionService.class);
    private SignUpHandler handler;

    private final Session session =
            new Session(IdGenerator.generate()).setState(SessionState.USER_NOT_FOUND);

    @BeforeEach
    public void setUp() {
        handler = new SignUpHandler(authenticationService, validationService, sessionService);
    }

    @Test
    public void shouldReturn200IfSignUpIsSuccessful() throws JsonProcessingException {
        session.setState(EMAIL_CODE_VERIFIED);
        String password = "computer-1";
        when(validationService.validatePassword(eq(password))).thenReturn(Optional.empty());
        when(authenticationService.userExists(eq("joe.bloggs@test.com"))).thenReturn(false);
        usingValidSession();
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("Session-Id", session.getSessionId()));
        event.setBody("{ \"password\": \"computer-1\", \"email\": \"joe.bloggs@test.com\" }");
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        verify(authenticationService)
                .signUp(eq("joe.bloggs@test.com"), eq(password), any(Subject.class));
        verify(sessionService)
                .save(
                        argThat(
                                (session) ->
                                        session.getState().equals(TWO_FACTOR_REQUIRED)
                                                && session.getEmailAddress()
                                                        .equals("joe.bloggs@test.com")));

        assertThat(result, hasStatus(200));
        BaseAPIResponse response =
                new ObjectMapper().readValue(result.getBody(), BaseAPIResponse.class);
        assertThat(response.getSessionState(), equalTo(TWO_FACTOR_REQUIRED));
    }

    @Test
    public void shouldReturn400IfSessionIdMissing() {
        String password = "computer-1";
        when(validationService.validatePassword(eq(password))).thenReturn(Optional.empty());

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody("{ \"password\": \"computer-1\", \"email\": \"joe.bloggs@test.com\" }");
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1000));
    }

    @Test
    public void shouldReturn400IfAnyRequestParametersAreMissing() {
        session.setState(EMAIL_CODE_VERIFIED);
        usingValidSession();
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("Session-Id", session.getSessionId()));
        event.setBody("{ \"email\": \"joe.bloggs@test.com\" }");
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1001));
    }

    @Test
    public void shouldReturn400IfPasswordFailsValidation() {
        session.setState(EMAIL_CODE_VERIFIED);
        String password = "computer";
        when(validationService.validatePassword(eq(password)))
                .thenReturn(Optional.of(ErrorResponse.ERROR_1007));

        usingValidSession();
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("Session-Id", session.getSessionId()));
        event.setBody("{ \"password\": \"computer\", \"email\": \"joe.bloggs@test.com\" }");
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1007));
    }

    @Test
    public void shouldReturn400IfUserAlreadyExists() {
        session.setState(EMAIL_CODE_VERIFIED);
        String password = "computer-1";
        when(validationService.validatePassword(eq(password))).thenReturn(Optional.empty());
        when(authenticationService.userExists(eq("joe.bloggs@test.com"))).thenReturn(true);

        usingValidSession();
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("Session-Id", "a-session-id"));
        event.setBody("{ \"password\": \"computer\", \"email\": \"joe.bloggs@test.com\" }");
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1009));
    }

    @Test
    public void shouldReturn400IfUserTransitionsToHelperFromWrongState() {
        session.setState(NEW);

        String password = "computer-1";
        when(validationService.validatePassword(eq(password))).thenReturn(Optional.empty());
        when(authenticationService.userExists(eq("joe.bloggs@test.com"))).thenReturn(false);
        usingValidSession();
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("Session-Id", session.getSessionId()));
        event.setBody("{ \"password\": \"computer-1\", \"email\": \"joe.bloggs@test.com\" }");
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1017));
    }

    private void usingValidSession() {
        when(sessionService.getSessionFromRequestHeaders(anyMap()))
                .thenReturn(Optional.of(session));
    }
}
