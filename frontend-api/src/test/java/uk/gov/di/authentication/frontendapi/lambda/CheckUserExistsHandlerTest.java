package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent;
import uk.gov.di.authentication.frontendapi.entity.CheckUserExistsResponse;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.Session;
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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.sharedtest.helper.RequestEventHelper.contextWithSourceIp;
import static uk.gov.di.authentication.sharedtest.logging.LogEventMatcher.withMessageContaining;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;

class CheckUserExistsHandlerTest {

    private final Context context = mock(Context.class);
    private final AuthenticationService authenticationService = mock(AuthenticationService.class);
    private final ValidationService validationService = mock(ValidationService.class);
    private final AuditService auditService = mock(AuditService.class);
    private final SessionService sessionService = mock(SessionService.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final ClientSessionService clientSessionService = mock(ClientSessionService.class);
    private final ClientService clientService = mock(ClientService.class);

    private CheckUserExistsHandler handler;
    private final ObjectMapper objectMapper = new ObjectMapper();

    private final Session session = new Session(IdGenerator.generate());

    @RegisterExtension
    public final CaptureLoggingExtension logging =
            new CaptureLoggingExtension(CheckUserExistsHandler.class);

    @AfterEach
    public void tearDown() {
        assertThat(logging.events(), not(hasItem(withMessageContaining(session.getSessionId()))));
    }

    @BeforeEach
    public void setup() {
        when(context.getAwsRequestId()).thenReturn("aws-session-id");

        handler =
                new CheckUserExistsHandler(
                        configurationService,
                        sessionService,
                        clientSessionService,
                        clientService,
                        authenticationService,
                        validationService,
                        auditService);
        reset(authenticationService);
    }

    @Test
    public void shouldReturn200IfUserExists() throws JsonProcessingException {
        usingValidSession();
        String persistentId = "some-persistent-id-value";
        Map<String, String> headers = new HashMap<>();
        headers.put(PersistentIdHelper.PERSISTENT_ID_HEADER_NAME, persistentId);
        headers.put("Session-Id", session.getSessionId());
        when(authenticationService.userExists(eq("joe.bloggs@digital.cabinet-office.gov.uk")))
                .thenReturn(true);
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody("{ \"email\": \"joe.bloggs@digital.cabinet-office.gov.uk\" }");
        event.setHeaders(headers);
        event.setRequestContext(contextWithSourceIp("123.123.123.123"));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertEquals(200, result.getStatusCode());

        CheckUserExistsResponse checkUserExistsResponse =
                objectMapper.readValue(result.getBody(), CheckUserExistsResponse.class);
        assertEquals(
                "joe.bloggs@digital.cabinet-office.gov.uk", checkUserExistsResponse.getEmail());
        assertTrue(checkUserExistsResponse.doesUserExist());

        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.CHECK_USER_KNOWN_EMAIL,
                        "aws-session-id",
                        session.getSessionId(),
                        "",
                        auditService.UNKNOWN,
                        "joe.bloggs@digital.cabinet-office.gov.uk",
                        "123.123.123.123",
                        "",
                        persistentId);
    }

    @Test
    public void shouldReturn200IfUserDoesNotExist() throws JsonProcessingException {
        usingValidSession();
        when(authenticationService.userExists(eq("joe.bloggs@digital.cabinet-office.gov.uk")))
                .thenReturn(false);

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody("{ \"email\": \"joe.bloggs@digital.cabinet-office.gov.uk\" }");
        event.setHeaders(Map.of("Session-Id", session.getSessionId()));
        event.setRequestContext(contextWithSourceIp("123.123.123.123"));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertEquals(200, result.getStatusCode());

        CheckUserExistsResponse checkUserExistsResponse =
                objectMapper.readValue(result.getBody(), CheckUserExistsResponse.class);
        assertEquals(
                "joe.bloggs@digital.cabinet-office.gov.uk", checkUserExistsResponse.getEmail());
        assertFalse(checkUserExistsResponse.doesUserExist());

        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.CHECK_USER_NO_ACCOUNT_WITH_EMAIL,
                        "aws-session-id",
                        session.getSessionId(),
                        "",
                        auditService.UNKNOWN,
                        "joe.bloggs@digital.cabinet-office.gov.uk",
                        "123.123.123.123",
                        AuditService.UNKNOWN,
                        PersistentIdHelper.PERSISTENT_ID_UNKNOWN_VALUE);
    }

    @Test
    public void shouldReturn400IfRequestIsMissingEmail() {
        usingValidSession();

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody("{ }");
        event.setHeaders(Map.of("Session-Id", session.getSessionId()));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertEquals(400, result.getStatusCode());
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1001));

        verifyNoInteractions(auditService);
    }

    @Test
    public void shouldReturn400IfRequestIsMissingSessionId() {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody("{ \"email\": \"joe.bloggs@digital.cabinet-office.gov.uk\" }");

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertEquals(400, result.getStatusCode());
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1000));

        verifyNoInteractions(auditService);
    }

    @Test
    public void shouldReturn400IfEmailAddressIsInvalid() {
        usingValidSession();
        when(validationService.validateEmailAddress(eq("joe.bloggs")))
                .thenReturn(Optional.of(ErrorResponse.ERROR_1004));

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody("{ \"email\": \"joe.bloggs\" }");
        event.setHeaders(Map.of("Session-Id", session.getSessionId()));
        event.setRequestContext(contextWithSourceIp("123.123.123.123"));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertEquals(400, result.getStatusCode());
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1004));

        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.CHECK_USER_INVALID_EMAIL,
                        "aws-session-id",
                        session.getSessionId(),
                        "",
                        auditService.UNKNOWN,
                        "joe.bloggs",
                        "123.123.123.123",
                        AuditService.UNKNOWN,
                        PersistentIdHelper.PERSISTENT_ID_UNKNOWN_VALUE);
    }

    @Test
    public void shouldReturn200IfUserTransitionsFromUserNotFoundAndUserDoesNotExist()
            throws JsonProcessingException {
        usingValidSession();
        when(authenticationService.userExists(eq("joe.bloggs"))).thenReturn(false);

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody("{ \"email\": \"joe.bloggs\" }");
        event.setHeaders(Map.of("Session-Id", session.getSessionId()));
        event.setRequestContext(contextWithSourceIp("123.123.123.123"));

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertEquals(200, result.getStatusCode());
        CheckUserExistsResponse checkUserExistsResponse =
                objectMapper.readValue(result.getBody(), CheckUserExistsResponse.class);
        assertEquals("joe.bloggs", checkUserExistsResponse.getEmail());
        assertFalse(checkUserExistsResponse.doesUserExist());

        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.CHECK_USER_NO_ACCOUNT_WITH_EMAIL,
                        "aws-session-id",
                        session.getSessionId(),
                        "",
                        auditService.UNKNOWN,
                        "joe.bloggs",
                        "123.123.123.123",
                        AuditService.UNKNOWN,
                        PersistentIdHelper.PERSISTENT_ID_UNKNOWN_VALUE);
    }

    private void usingValidSession() {
        when(sessionService.getSessionFromRequestHeaders(anyMap()))
                .thenReturn(Optional.of(session));
    }
}
