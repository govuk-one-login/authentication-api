package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.TermsAndConditions;
import uk.gov.di.authentication.shared.helpers.IdGenerator;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.SessionService;
import uk.gov.di.authentication.shared.services.ValidationService;
import uk.gov.di.authentication.sharedtest.logging.CaptureLoggingExtension;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.not;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.sharedtest.helper.RequestEventHelper.contextWithSourceIp;
import static uk.gov.di.authentication.sharedtest.logging.LogEventMatcher.withMessageContaining;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class SignUpHandlerTest {

    private final Context context = mock(Context.class);
    private final AuthenticationService authenticationService = mock(AuthenticationService.class);
    private final ValidationService validationService = mock(ValidationService.class);
    private final SessionService sessionService = mock(SessionService.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final ClientSessionService clientSessionService = mock(ClientSessionService.class);
    private final ClientService clientService = mock(ClientService.class);
    private final AuditService auditService = mock(AuditService.class);

    private SignUpHandler handler;

    private final Session session = new Session(IdGenerator.generate());

    @RegisterExtension
    private final CaptureLoggingExtension logging =
            new CaptureLoggingExtension(SignUpHandler.class);

    @AfterEach
    void tearDown() {
        assertThat(logging.events(), not(hasItem(withMessageContaining(session.getSessionId()))));
    }

    @BeforeEach
    void setUp() {
        when(configurationService.getTermsAndConditionsVersion()).thenReturn("1.0");
        handler =
                new SignUpHandler(
                        configurationService,
                        sessionService,
                        clientSessionService,
                        clientService,
                        authenticationService,
                        validationService,
                        auditService);
    }

    @Test
    void shouldReturn204IfSignUpIsSuccessful() {
        String email = "joe.bloggs@test.com";
        String password = "computer-1";
        String persistentId = "some-persistent-id-value";
        Map<String, String> headers = new HashMap<>();
        headers.put(PersistentIdHelper.PERSISTENT_ID_HEADER_NAME, persistentId);
        headers.put("Session-Id", session.getSessionId());
        when(validationService.validatePassword(eq(password))).thenReturn(Optional.empty());
        when(authenticationService.userExists(eq("joe.bloggs@test.com"))).thenReturn(false);
        usingValidSession();
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setRequestContext(contextWithSourceIp("123.123.123.123"));
        event.setHeaders(headers);
        event.setBody(
                format("{ \"password\": \"computer-1\", \"email\": \"%s\" }", email.toUpperCase()));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        verify(authenticationService)
                .signUp(
                        eq("joe.bloggs@test.com"),
                        eq(password),
                        any(Subject.class),
                        any(TermsAndConditions.class));
        verify(sessionService)
                .save(
                        argThat(
                                (session) ->
                                        session.getEmailAddress().equals("joe.bloggs@test.com")));

        assertThat(result, hasStatus(204));
        verify(authenticationService)
                .signUp(
                        eq(email),
                        eq("computer-1"),
                        any(Subject.class),
                        any(TermsAndConditions.class));

        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.CREATE_ACCOUNT,
                        context.getAwsRequestId(),
                        session.getSessionId(),
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        "joe.bloggs@test.com",
                        "123.123.123.123",
                        AuditService.UNKNOWN,
                        persistentId);

        verify(sessionService)
                .save(argThat(session -> session.isNewAccount() == Session.AccountState.NEW));
    }

    @Test
    void shouldReturn400IfSessionIdMissing() {
        String password = "computer-1";
        when(validationService.validatePassword(eq(password))).thenReturn(Optional.empty());

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody("{ \"password\": \"computer-1\", \"email\": \"joe.bloggs@test.com\" }");
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1000));

        verifyNoInteractions(auditService);
    }

    @Test
    void shouldReturn400IfAnyRequestParametersAreMissing() {
        usingValidSession();
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("Session-Id", session.getSessionId()));
        event.setBody("{ \"email\": \"joe.bloggs@test.com\" }");
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1001));

        verifyNoInteractions(auditService);
    }

    @Test
    void shouldReturn400IfPasswordFailsValidation() {
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

        verifyNoInteractions(auditService);
    }

    @Test
    void shouldReturn400IfUserAlreadyExists() {
        String password = "computer-1";
        when(validationService.validatePassword(eq(password))).thenReturn(Optional.empty());
        when(authenticationService.userExists(eq("joe.bloggs@test.com"))).thenReturn(true);

        usingValidSession();
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setRequestContext(contextWithSourceIp("123.123.123.123"));
        event.setHeaders(Map.of("Session-Id", "a-session-id"));
        event.setBody("{ \"password\": \"computer\", \"email\": \"joe.bloggs@test.com\" }");
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1009));

        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.CREATE_ACCOUNT_EMAIL_ALREADY_EXISTS,
                        context.getAwsRequestId(),
                        session.getSessionId(),
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        "joe.bloggs@test.com",
                        "123.123.123.123",
                        AuditService.UNKNOWN,
                        PersistentIdHelper.PERSISTENT_ID_UNKNOWN_VALUE);
    }

    private void usingValidSession() {
        when(sessionService.getSessionFromRequestHeaders(anyMap()))
                .thenReturn(Optional.of(session));
    }
}
