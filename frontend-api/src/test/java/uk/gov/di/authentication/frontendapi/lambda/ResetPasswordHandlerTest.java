package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.frontendapi.services.AwsSqsClient;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.NotificationType;
import uk.gov.di.authentication.shared.entity.NotifyRequest;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.UserCredentials;
import uk.gov.di.authentication.shared.helpers.Argon2EncoderHelper;
import uk.gov.di.authentication.shared.helpers.IdGenerator;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.SessionService;
import uk.gov.di.authentication.shared.services.ValidationService;

import java.util.Map;
import java.util.Optional;

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class ResetPasswordHandlerTest {

    private final AuthenticationService authenticationService = mock(AuthenticationService.class);
    private final AwsSqsClient sqsClient = mock(AwsSqsClient.class);
    private final CodeStorageService codeStorageService = mock(CodeStorageService.class);
    private final ValidationService validationService = mock(ValidationService.class);
    private final SessionService sessionService = mock(SessionService.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final ClientService clientService = mock(ClientService.class);
    private final ClientSessionService clientSessionService = mock(ClientSessionService.class);
    private final Context context = mock(Context.class);
    private static final String CODE = "12345678901";
    private static final String NEW_PASSWORD = "Pa55word!";
    private static final String SUBJECT = "some-subject";
    private static final String EMAIL = "joe.bloggs@digital.cabinet-office.gov.uk";
    private ResetPasswordHandler handler;
    private final Session session = new Session(IdGenerator.generate()).setEmailAddress(EMAIL);

    @BeforeEach
    public void setUp() {
        handler =
                new ResetPasswordHandler(
                        authenticationService,
                        sqsClient,
                        codeStorageService,
                        validationService,
                        configurationService,
                        sessionService,
                        clientSessionService,
                        clientService);
    }

    @Test
    public void shouldReturn204ForSuccessfulRequest() throws JsonProcessingException {
        when(codeStorageService.getSubjectWithPasswordResetCode(CODE))
                .thenReturn(Optional.of(SUBJECT));
        when(authenticationService.getUserCredentialsFromSubject(SUBJECT))
                .thenReturn(generateUserCredentials());
        usingValidSession();
        NotifyRequest notifyRequest =
                new NotifyRequest(EMAIL, NotificationType.PASSWORD_RESET_CONFIRMATION);
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("Session-Id", session.getSessionId()));
        event.setBody(format("{ \"code\": \"%s\", \"password\": \"%s\"}", CODE, NEW_PASSWORD));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(204));
        verify(sqsClient, times(1)).send(new ObjectMapper().writeValueAsString(notifyRequest));
        verify(authenticationService, times(1)).updatePassword(EMAIL, NEW_PASSWORD);
        verify(codeStorageService, times(1)).deleteSubjectWithPasswordResetCode(CODE);
    }

    @Test
    public void shouldReturn204ForSuccessfulMigratedUserRequest() throws JsonProcessingException {
        when(codeStorageService.getSubjectWithPasswordResetCode(CODE))
                .thenReturn(Optional.of(SUBJECT));
        when(authenticationService.getUserCredentialsFromSubject(SUBJECT))
                .thenReturn(generateMigratedUserCredentials());
        usingValidSession();
        NotifyRequest notifyRequest =
                new NotifyRequest(EMAIL, NotificationType.PASSWORD_RESET_CONFIRMATION);
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody(format("{ \"code\": \"%s\", \"password\": \"%s\"}", CODE, NEW_PASSWORD));
        event.setHeaders(Map.of("Session-Id", session.getSessionId()));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(204));
        verify(sqsClient, times(1)).send(new ObjectMapper().writeValueAsString(notifyRequest));
        verify(authenticationService, times(1)).updatePassword(EMAIL, NEW_PASSWORD);
        verify(codeStorageService, times(1)).deleteSubjectWithPasswordResetCode(CODE);
    }

    @Test
    public void shouldReturn400ForRequestIsMissingParameters() {
        usingValidSession();
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody(format("{ \"code\": \"%s\"}", CODE));
        event.setHeaders(Map.of("Session-Id", session.getSessionId()));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1001));
    }

    @Test
    public void shouldReturn400IfPasswordFailsValidation() {
        usingValidSession();
        String invalidPassword = "password";
        when(validationService.validatePassword(invalidPassword))
                .thenReturn(Optional.of(ErrorResponse.ERROR_1007));
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody(format("{ \"code\": \"%s\", \"password\": \"%s\"}", CODE, "password"));
        event.setHeaders(Map.of("Session-Id", session.getSessionId()));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1007));
        verify(authenticationService, never()).updatePassword(EMAIL, NEW_PASSWORD);
    }

    @Test
    public void shouldReturn400IfNewPasswordEqualsExistingPassword()
            throws JsonProcessingException {
        usingValidSession();
        when(codeStorageService.getSubjectWithPasswordResetCode(CODE))
                .thenReturn(Optional.of(SUBJECT));
        when(authenticationService.getUserCredentialsFromSubject(SUBJECT))
                .thenReturn(generateUserCredentials(Argon2EncoderHelper.argon2Hash(NEW_PASSWORD)));
        NotifyRequest notifyRequest =
                new NotifyRequest(EMAIL, NotificationType.PASSWORD_RESET_CONFIRMATION);
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody(format("{ \"code\": \"%s\", \"password\": \"%s\"}", CODE, NEW_PASSWORD));
        event.setHeaders(Map.of("Session-Id", session.getSessionId()));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1024));
        verify(sqsClient, never()).send(new ObjectMapper().writeValueAsString(notifyRequest));
        verify(authenticationService, never()).updatePassword(EMAIL, NEW_PASSWORD);
        verify(codeStorageService, never()).deleteSubjectWithPasswordResetCode(CODE);
    }

    @Test
    public void shouldReturn400WhenCodeIsInvalid() {
        usingValidSession();
        when(codeStorageService.getSubjectWithPasswordResetCode(CODE)).thenReturn(Optional.empty());

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody(format("{ \"code\": \"%s\", \"password\": \"%s\"}", CODE, NEW_PASSWORD));
        event.setHeaders(Map.of("Session-Id", session.getSessionId()));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1021));
        verify(authenticationService, never()).updatePassword(EMAIL, NEW_PASSWORD);
    }

    @Test
    public void shouldDeleteIncorrectPasswordCountOnSuccessfulRequest() {
        usingValidSession();
        when(codeStorageService.getSubjectWithPasswordResetCode(CODE))
                .thenReturn(Optional.of(SUBJECT));
        when(codeStorageService.getIncorrectPasswordCount(EMAIL)).thenReturn(2);
        when(authenticationService.getUserCredentialsFromSubject(SUBJECT))
                .thenReturn(generateUserCredentials());
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody(format("{ \"code\": \"%s\", \"password\": \"%s\"}", CODE, NEW_PASSWORD));
        event.setHeaders(Map.of("Session-Id", session.getSessionId()));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(204));
        verify(codeStorageService, times(1)).deleteSubjectWithPasswordResetCode(CODE);
        verify(codeStorageService, times(1)).deleteIncorrectPasswordCount(EMAIL);
    }

    @Test
    public void shouldReturn400WhenUserHasInvalidSession() {
        when(codeStorageService.getSubjectWithPasswordResetCode(CODE))
                .thenReturn(Optional.of(SUBJECT));
        when(authenticationService.getUserCredentialsFromSubject(SUBJECT))
                .thenReturn(generateUserCredentials());
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("Session-Id", session.getSessionId()));
        event.setBody(format("{ \"code\": \"%s\", \"password\": \"%s\"}", CODE, NEW_PASSWORD));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1000));
        verify(authenticationService, never()).updatePassword(EMAIL, NEW_PASSWORD);
        verify(codeStorageService, never()).deleteSubjectWithPasswordResetCode(CODE);
    }

    private UserCredentials generateUserCredentials() {
        return generateUserCredentials("old-password1");
    }

    private UserCredentials generateUserCredentials(String password) {
        return new UserCredentials().setEmail(EMAIL).setPassword(password).setSubjectID(SUBJECT);
    }

    private UserCredentials generateMigratedUserCredentials() {
        return new UserCredentials()
                .setEmail(EMAIL)
                .setMigratedPassword("old-password1")
                .setSubjectID(SUBJECT);
    }

    private void usingValidSession() {
        when(sessionService.getSessionFromRequestHeaders(anyMap()))
                .thenReturn(Optional.of(session));
    }
}
