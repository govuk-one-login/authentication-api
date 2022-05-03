package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.mockito.Mockito;
import software.amazon.awssdk.core.exception.SdkClientException;
import uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent;
import uk.gov.di.authentication.frontendapi.services.ResetPasswordService;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.NotificationType;
import uk.gov.di.authentication.shared.entity.NotifyRequest;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.helpers.IdGenerator;
import uk.gov.di.authentication.shared.helpers.ObjectMapperFactory;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.AwsSqsClient;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.CodeGeneratorService;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.SessionService;
import uk.gov.di.authentication.sharedtest.logging.CaptureLoggingExtension;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.shared.entity.NotificationType.RESET_PASSWORD;
import static uk.gov.di.authentication.shared.entity.NotificationType.RESET_PASSWORD_WITH_CODE;
import static uk.gov.di.authentication.shared.services.CodeStorageService.PASSWORD_RESET_BLOCKED_KEY_PREFIX;
import static uk.gov.di.authentication.sharedtest.helper.RequestEventHelper.contextWithSourceIp;
import static uk.gov.di.authentication.sharedtest.logging.LogEventMatcher.withMessageContaining;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;

class ResetPasswordRequestHandlerTest {

    private static final String TEST_EMAIL_ADDRESS = "joe.bloggs@digital.cabinet-office.gov.uk";
    private static final String TEST_SIX_DIGIT_CODE = "123456";
    private static final String TEST_RESET_PASSWORD_LINK =
            "https://localhost:8080/frontend?reset-password?code=123456.54353464565";
    private static final long CODE_EXPIRY_TIME = 900;
    private static final long BLOCKED_EMAIL_DURATION = 799;
    private static final ObjectMapper objectMapper = ObjectMapperFactory.getInstance();

    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final AwsSqsClient awsSqsClient = mock(AwsSqsClient.class);
    private final SessionService sessionService = mock(SessionService.class);
    private final CodeGeneratorService codeGeneratorService = mock(CodeGeneratorService.class);
    private final CodeStorageService codeStorageService = mock(CodeStorageService.class);
    private final AuthenticationService authenticationService = mock(AuthenticationService.class);
    private final ClientSessionService clientSessionService = mock(ClientSessionService.class);
    private final ResetPasswordService resetPasswordService = mock(ResetPasswordService.class);
    private final ClientService clientService = mock(ClientService.class);
    private final AuditService auditService = mock(AuditService.class);
    private final Context context = mock(Context.class);

    private final Session session =
            new Session(IdGenerator.generate()).setEmailAddress(TEST_EMAIL_ADDRESS);
    private final ResetPasswordRequestHandler handler =
            new ResetPasswordRequestHandler(
                    configurationService,
                    sessionService,
                    clientSessionService,
                    clientService,
                    authenticationService,
                    awsSqsClient,
                    codeGeneratorService,
                    codeStorageService,
                    auditService,
                    resetPasswordService);

    @RegisterExtension
    public final CaptureLoggingExtension logging =
            new CaptureLoggingExtension(ResetPasswordRequestHandler.class);

    @AfterEach
    public void tearDown() {
        assertThat(
                logging.events(),
                not(hasItem(withMessageContaining(session.getSessionId(), TEST_EMAIL_ADDRESS))));
    }

    @BeforeEach
    void setup() {
        when(configurationService.getCodeExpiry()).thenReturn(CODE_EXPIRY_TIME);
        when(codeGeneratorService.twentyByteEncodedRandomCode()).thenReturn(TEST_SIX_DIGIT_CODE);
        when(codeGeneratorService.sixDigitCode()).thenReturn(TEST_SIX_DIGIT_CODE);
        when(configurationService.getCodeMaxRetries()).thenReturn(5);
    }

    @Test
    void shouldReturn200AndPutMessageOnQueueForAValidLinkFlowRequest()
            throws JsonProcessingException {
        String persistentId = "some-persistent-id-value";
        Map<String, String> headers = new HashMap<>();
        headers.put(PersistentIdHelper.PERSISTENT_ID_HEADER_NAME, persistentId);
        headers.put("Session-Id", session.getSessionId());
        Subject subject = new Subject("subject_1");
        when(authenticationService.getSubjectFromEmail(TEST_EMAIL_ADDRESS)).thenReturn(subject);
        when(resetPasswordService.buildResetPasswordLink(
                        TEST_SIX_DIGIT_CODE, session.getSessionId(), persistentId))
                .thenReturn(TEST_RESET_PASSWORD_LINK);
        NotifyRequest notifyRequest =
                new NotifyRequest(TEST_EMAIL_ADDRESS, RESET_PASSWORD, TEST_RESET_PASSWORD_LINK);
        String serialisedRequest = objectMapper.writeValueAsString(notifyRequest);

        usingValidSession();
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setRequestContext(contextWithSourceIp("123.123.123.123"));
        event.setHeaders(headers);
        event.setBody(format("{ \"email\": \"%s\" }", TEST_EMAIL_ADDRESS));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertEquals(204, result.getStatusCode());

        verify(awsSqsClient).send(serialisedRequest);
        verify(codeStorageService)
                .savePasswordResetCode(
                        subject.getValue(), TEST_SIX_DIGIT_CODE, CODE_EXPIRY_TIME, RESET_PASSWORD);
        verify(sessionService).save(argThat(this::isSessionWithEmailSent));

        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.PASSWORD_RESET_REQUESTED,
                        context.getAwsRequestId(),
                        session.getSessionId(),
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        TEST_EMAIL_ADDRESS,
                        "123.123.123.123",
                        AuditService.UNKNOWN,
                        persistentId);
    }

    @Test
    void shouldReturn200AndPutMessageOnQueueForAValidCodeFlowRequest()
            throws JsonProcessingException {
        String persistentId = "some-persistent-id-value";
        Map<String, String> headers = new HashMap<>();
        headers.put(PersistentIdHelper.PERSISTENT_ID_HEADER_NAME, persistentId);
        headers.put("Session-Id", session.getSessionId());
        Subject subject = new Subject("subject_1");
        when(authenticationService.getSubjectFromEmail(TEST_EMAIL_ADDRESS)).thenReturn(subject);
        NotifyRequest notifyRequest =
                new NotifyRequest(
                        TEST_EMAIL_ADDRESS, RESET_PASSWORD_WITH_CODE, TEST_SIX_DIGIT_CODE);
        String serialisedRequest = objectMapper.writeValueAsString(notifyRequest);

        usingValidSession();
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setRequestContext(contextWithSourceIp("123.123.123.123"));
        event.setHeaders(headers);
        event.setBody(format("{ \"email\": \"%s\", \"useCodeFlow\": true }", TEST_EMAIL_ADDRESS));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertEquals(204, result.getStatusCode());

        verify(awsSqsClient).send(serialisedRequest);
        verify(codeStorageService)
                .saveOtpCode(
                        TEST_EMAIL_ADDRESS,
                        TEST_SIX_DIGIT_CODE,
                        CODE_EXPIRY_TIME,
                        RESET_PASSWORD_WITH_CODE);
        verify(sessionService).save(argThat(this::isSessionWithEmailSent));

        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.PASSWORD_RESET_REQUESTED,
                        context.getAwsRequestId(),
                        session.getSessionId(),
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        TEST_EMAIL_ADDRESS,
                        "123.123.123.123",
                        AuditService.UNKNOWN,
                        persistentId);
    }

    @Test
    void shouldReturn400IfInvalidSessionProvided() {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody(format("{ \"email\": \"%s\" }", TEST_EMAIL_ADDRESS));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertEquals(400, result.getStatusCode());

        verify(awsSqsClient, never()).send(anyString());
        verify(codeStorageService, never())
                .saveOtpCode(anyString(), anyString(), anyLong(), any(NotificationType.class));
        verify(sessionService, never()).save(argThat(this::isSessionWithEmailSent));
    }

    @Test
    public void shouldReturn400IfRequestIsMissingEmail() {
        usingValidSession();
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("Session-Id", session.getSessionId()));
        event.setBody("{ }");
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertEquals(400, result.getStatusCode());
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1001));
    }

    @Test
    public void shouldReturn500IfMessageCannotBeSentToQueue() throws JsonProcessingException {
        String persistentId = "some-persistent-id-value";
        Subject subject = new Subject("subject_1");
        when(authenticationService.getSubjectFromEmail(TEST_EMAIL_ADDRESS)).thenReturn(subject);
        when(resetPasswordService.buildResetPasswordLink(
                        TEST_SIX_DIGIT_CODE, session.getSessionId(), persistentId))
                .thenReturn(TEST_RESET_PASSWORD_LINK);
        NotifyRequest notifyRequest =
                new NotifyRequest(TEST_EMAIL_ADDRESS, RESET_PASSWORD, TEST_RESET_PASSWORD_LINK);
        String serialisedRequest = objectMapper.writeValueAsString(notifyRequest);
        Mockito.doThrow(SdkClientException.class).when(awsSqsClient).send(eq(serialisedRequest));

        usingValidSession();
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        Map<String, String> headers = new HashMap<>();
        headers.put(PersistentIdHelper.PERSISTENT_ID_HEADER_NAME, persistentId);
        headers.put("Session-Id", session.getSessionId());
        event.setHeaders(headers);
        event.setBody(format("{ \"email\": \"%s\" }", TEST_EMAIL_ADDRESS));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertEquals(500, result.getStatusCode());
        assertTrue(result.getBody().contains("Error sending message to queue"));
    }

    @Test
    public void shouldReturn400IfUserHasExceededPasswordResetCount() {
        Subject subject = new Subject("subject_1");
        String sessionId = "1233455677";
        when(authenticationService.getSubjectFromEmail(TEST_EMAIL_ADDRESS)).thenReturn(subject);
        when(configurationService.getBlockedEmailDuration()).thenReturn(BLOCKED_EMAIL_DURATION);
        Session session = mock(Session.class);
        when(session.getEmailAddress()).thenReturn(TEST_EMAIL_ADDRESS);
        when(session.getSessionId()).thenReturn(sessionId);
        when(session.validateSession(TEST_EMAIL_ADDRESS)).thenReturn(true);
        when(session.getPasswordResetCount()).thenReturn(5);

        when(sessionService.getSessionFromRequestHeaders(anyMap()))
                .thenReturn(Optional.of(session));

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("Session-Id", sessionId));
        event.setBody(format("{ \"email\": \"%s\" }", TEST_EMAIL_ADDRESS));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertEquals(400, result.getStatusCode());
        verify(codeStorageService)
                .saveBlockedForEmail(
                        TEST_EMAIL_ADDRESS,
                        PASSWORD_RESET_BLOCKED_KEY_PREFIX,
                        BLOCKED_EMAIL_DURATION);
        verify(session).resetPasswordResetCount();
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1022));
    }

    @Test
    public void shouldReturn400IfUserIsBlockedFromRequestingAnyMorePasswordResets() {
        Subject subject = new Subject("subject_1");
        String sessionId = "1233455677";
        when(authenticationService.getSubjectFromEmail(TEST_EMAIL_ADDRESS)).thenReturn(subject);
        Session session = mock(Session.class);
        when(session.getEmailAddress()).thenReturn(TEST_EMAIL_ADDRESS);
        when(session.getSessionId()).thenReturn(sessionId);
        when(session.validateSession(TEST_EMAIL_ADDRESS)).thenReturn(true);
        when(session.getPasswordResetCount()).thenReturn(0);
        when(codeStorageService.isBlockedForEmail(
                        TEST_EMAIL_ADDRESS, PASSWORD_RESET_BLOCKED_KEY_PREFIX))
                .thenReturn(true);
        when(sessionService.getSessionFromRequestHeaders(anyMap()))
                .thenReturn(Optional.of(session));

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("Session-Id", sessionId));
        event.setBody(format("{ \"email\": \"%s\" }", TEST_EMAIL_ADDRESS));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertEquals(400, result.getStatusCode());
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1023));
    }

    private void usingValidSession() {
        when(sessionService.getSessionFromRequestHeaders(anyMap()))
                .thenReturn(Optional.of(session));
    }

    private boolean isSessionWithEmailSent(Session session) {
        return session.getEmailAddress().equals(TEST_EMAIL_ADDRESS);
    }
}
