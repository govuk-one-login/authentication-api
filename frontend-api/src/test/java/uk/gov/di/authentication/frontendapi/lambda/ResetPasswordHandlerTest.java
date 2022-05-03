package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.NotificationType;
import uk.gov.di.authentication.shared.entity.NotifyRequest;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.UserCredentials;
import uk.gov.di.authentication.shared.helpers.Argon2EncoderHelper;
import uk.gov.di.authentication.shared.helpers.IdGenerator;
import uk.gov.di.authentication.shared.helpers.ObjectMapperFactory;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.AwsSqsClient;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.SessionService;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.sharedtest.helper.RequestEventHelper.contextWithSourceIp;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class ResetPasswordHandlerTest {

    private final AuthenticationService authenticationService = mock(AuthenticationService.class);
    private final AwsSqsClient sqsClient = mock(AwsSqsClient.class);
    private final CodeStorageService codeStorageService = mock(CodeStorageService.class);
    private final SessionService sessionService = mock(SessionService.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final ClientService clientService = mock(ClientService.class);
    private final ClientSessionService clientSessionService = mock(ClientSessionService.class);
    private final AuditService auditService = mock(AuditService.class);
    private final Context context = mock(Context.class);
    private static final String CODE = "12345678901";
    private static final String NEW_PASSWORD = "Pa55word!";
    private static final String SUBJECT = "some-subject";
    private static final String EMAIL = "joe.bloggs@digital.cabinet-office.gov.uk";
    private static final String PERSISTENT_ID = "some-persistent-id-value";
    private static final ObjectMapper objectMapper = ObjectMapperFactory.getInstance();

    private ResetPasswordHandler handler;
    private final Session session = new Session(IdGenerator.generate()).setEmailAddress(EMAIL);

    @BeforeEach
    public void setUp() {
        handler =
                new ResetPasswordHandler(
                        authenticationService,
                        sqsClient,
                        codeStorageService,
                        configurationService,
                        sessionService,
                        clientSessionService,
                        clientService,
                        auditService);
    }

    @Test
    public void shouldReturn204ForSuccessfulRequestContainingCode() throws JsonProcessingException {
        when(codeStorageService.getSubjectWithPasswordResetCode(CODE))
                .thenReturn(Optional.of(SUBJECT));
        when(authenticationService.getUserCredentialsFromSubject(SUBJECT))
                .thenReturn(generateUserCredentials());
        usingValidSession();
        NotifyRequest notifyRequest =
                new NotifyRequest(EMAIL, NotificationType.PASSWORD_RESET_CONFIRMATION);
        Map<String, String> headers = new HashMap<>();
        headers.put(PersistentIdHelper.PERSISTENT_ID_HEADER_NAME, PERSISTENT_ID);
        headers.put("Session-Id", session.getSessionId());
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(headers);
        event.setBody(format("{ \"code\": \"%s\", \"password\": \"%s\"}", CODE, NEW_PASSWORD));
        event.setRequestContext(contextWithSourceIp("123.123.123.123"));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(204));
        verify(sqsClient, times(1)).send(objectMapper.writeValueAsString(notifyRequest));
        verify(authenticationService, times(1)).updatePassword(EMAIL, NEW_PASSWORD);
        verify(codeStorageService, times(1)).deleteSubjectWithPasswordResetCode(CODE);

        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.PASSWORD_RESET_SUCCESSFUL,
                        context.getAwsRequestId(),
                        session.getSessionId(),
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        EMAIL,
                        "123.123.123.123",
                        AuditService.UNKNOWN,
                        PERSISTENT_ID);
    }

    @Test
    public void shouldReturn204ForSuccessfulRequestWithNoCode() throws JsonProcessingException {

        when(authenticationService.getUserCredentialsFromEmail(EMAIL))
                .thenReturn(generateUserCredentials());
        usingValidSession();
        NotifyRequest notifyRequest =
                new NotifyRequest(EMAIL, NotificationType.PASSWORD_RESET_CONFIRMATION);
        Map<String, String> headers = new HashMap<>();
        headers.put(PersistentIdHelper.PERSISTENT_ID_HEADER_NAME, PERSISTENT_ID);
        headers.put("Session-Id", session.getSessionId());
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(headers);
        event.setBody(format("{ \"password\": \"%s\"}", NEW_PASSWORD));
        event.setRequestContext(contextWithSourceIp("123.123.123.123"));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(204));
        verify(sqsClient, times(1)).send(objectMapper.writeValueAsString(notifyRequest));
        verify(authenticationService, times(1)).updatePassword(EMAIL, NEW_PASSWORD);

        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.PASSWORD_RESET_SUCCESSFUL,
                        context.getAwsRequestId(),
                        session.getSessionId(),
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        EMAIL,
                        "123.123.123.123",
                        AuditService.UNKNOWN,
                        PERSISTENT_ID);
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
        Map<String, String> headers = new HashMap<>();
        headers.put(PersistentIdHelper.PERSISTENT_ID_HEADER_NAME, PERSISTENT_ID);
        headers.put("Session-Id", session.getSessionId());
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody(format("{ \"code\": \"%s\", \"password\": \"%s\"}", CODE, NEW_PASSWORD));
        event.setHeaders(headers);
        event.setRequestContext(contextWithSourceIp("123.123.123.123"));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(204));
        verify(sqsClient, times(1)).send(objectMapper.writeValueAsString(notifyRequest));
        verify(authenticationService, times(1)).updatePassword(EMAIL, NEW_PASSWORD);
        verify(codeStorageService, times(1)).deleteSubjectWithPasswordResetCode(CODE);

        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.PASSWORD_RESET_SUCCESSFUL,
                        context.getAwsRequestId(),
                        session.getSessionId(),
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        EMAIL,
                        "123.123.123.123",
                        AuditService.UNKNOWN,
                        PERSISTENT_ID);
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

        verifyNoInteractions(auditService);
    }

    @Test
    public void shouldReturn400IfPasswordFailsValidation() {
        usingValidSession();
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody(format("{ \"code\": \"%s\", \"password\": \"%s\"}", CODE, "password"));
        event.setHeaders(Map.of("Session-Id", session.getSessionId()));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1007));
        verify(authenticationService, never()).updatePassword(EMAIL, NEW_PASSWORD);
        verifyNoInteractions(auditService);
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
        verify(sqsClient, never()).send(objectMapper.writeValueAsString(notifyRequest));
        verify(authenticationService, never()).updatePassword(EMAIL, NEW_PASSWORD);
        verify(codeStorageService, never()).deleteSubjectWithPasswordResetCode(CODE);
        verifyNoInteractions(auditService);
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
        verifyNoInteractions(auditService);
    }

    @Test
    public void shouldDeleteIncorrectPasswordCountOnSuccessfulRequest() {
        usingValidSession();
        when(codeStorageService.getSubjectWithPasswordResetCode(CODE))
                .thenReturn(Optional.of(SUBJECT));
        when(codeStorageService.getIncorrectPasswordCount(EMAIL)).thenReturn(2);
        when(authenticationService.getUserCredentialsFromSubject(SUBJECT))
                .thenReturn(generateUserCredentials());
        Map<String, String> headers = new HashMap<>();
        headers.put(PersistentIdHelper.PERSISTENT_ID_HEADER_NAME, PERSISTENT_ID);
        headers.put("Session-Id", session.getSessionId());
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody(format("{ \"code\": \"%s\", \"password\": \"%s\"}", CODE, NEW_PASSWORD));
        event.setHeaders(headers);
        event.setRequestContext(contextWithSourceIp("123.123.123.123"));

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(204));
        verify(codeStorageService, times(1)).deleteSubjectWithPasswordResetCode(CODE);
        verify(codeStorageService, times(1)).deleteIncorrectPasswordCount(EMAIL);
        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.PASSWORD_RESET_SUCCESSFUL,
                        context.getAwsRequestId(),
                        session.getSessionId(),
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        EMAIL,
                        "123.123.123.123",
                        AuditService.UNKNOWN,
                        PERSISTENT_ID);
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
        verifyNoInteractions(auditService);
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
