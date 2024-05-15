package uk.gov.di.accountmanagement.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.accountmanagement.domain.AccountManagementAuditableEvent;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthenticationService;

import java.util.Map;
import java.util.Optional;

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.sharedtest.helper.RequestEventHelper.contextWithSourceIp;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class AuthenticateHandlerTest {

    private static final String EMAIL = "computer-1";
    private static final String PASSWORD = "joe.bloggs@test.com";
    private static final String PHONE_NUMBER = "01234567890";
    private static final String IP_ADDRESS = "123.123.123.123";
    private AuthenticateHandler handler;
    private final Context context = mock(Context.class);
    private final AuthenticationService authenticationService = mock(AuthenticationService.class);
    private final AuditService auditService = mock(AuditService.class);

    @BeforeEach
    public void setUp() {
        handler = new AuthenticateHandler(authenticationService, auditService);
    }

    @Test
    public void shouldReturn204IfLoginIsSuccessful() {
        String persistentIdValue = "some-persistent-session-id";
        when(authenticationService.userExists(EMAIL)).thenReturn(true);
        when(authenticationService.login(EMAIL, PASSWORD)).thenReturn(true);
        when(authenticationService.getPhoneNumber(EMAIL)).thenReturn(Optional.of(PHONE_NUMBER));
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setRequestContext(contextWithSourceIp("123.123.123.123"));
        event.setHeaders(Map.of(PersistentIdHelper.PERSISTENT_ID_HEADER_NAME, persistentIdValue));
        event.setBody(format("{ \"password\": \"%s\", \"email\": \"%s\" }", PASSWORD, EMAIL));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(204));

        verify(auditService)
                .submitAuditEvent(
                        AccountManagementAuditableEvent.ACCOUNT_MANAGEMENT_AUTHENTICATE,
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        EMAIL,
                        IP_ADDRESS,
                        AuditService.UNKNOWN,
                        persistentIdValue,
                        AuditService.RestrictedSection.empty);
    }

    @Test
    public void shouldReturn401IfUserHasInvalidCredentials() {
        when(authenticationService.userExists(EMAIL)).thenReturn(true);
        String persistentIdValue = "some-persistent-session-id";
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody(format("{ \"password\": \"%s\", \"email\": \"%s\" }", PASSWORD, EMAIL));
        event.setRequestContext(contextWithSourceIp("123.123.123.123"));
        event.setHeaders(Map.of(PersistentIdHelper.PERSISTENT_ID_HEADER_NAME, persistentIdValue));
        when(authenticationService.login(EMAIL, PASSWORD)).thenReturn(false);

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(401));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1008));

        verify(auditService)
                .submitAuditEvent(
                        AccountManagementAuditableEvent.ACCOUNT_MANAGEMENT_AUTHENTICATE_FAILURE,
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        EMAIL,
                        IP_ADDRESS,
                        AuditService.UNKNOWN,
                        persistentIdValue,
                        AuditService.RestrictedSection.empty);
    }

    @Test
    public void shouldReturn400IfAnyRequestParametersAreMissing() {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        String persistentIdValue = "some-persistent-session-id";
        event.setBody(format("{ \"password\": \"%s\"}", PASSWORD));
        event.setRequestContext(contextWithSourceIp("123.123.123.123"));
        when(authenticationService.login(EMAIL, PASSWORD)).thenReturn(false);
        event.setHeaders(Map.of(PersistentIdHelper.PERSISTENT_ID_HEADER_NAME, persistentIdValue));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1001));

        verify(auditService)
                .submitAuditEvent(
                        AccountManagementAuditableEvent.ACCOUNT_MANAGEMENT_AUTHENTICATE_FAILURE,
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        IP_ADDRESS,
                        AuditService.UNKNOWN,
                        persistentIdValue,
                        AuditService.RestrictedSection.empty);
    }

    @Test
    public void shouldReturn400IfUserDoesNotHaveAnAccount() {
        String persistentIdValue = "some-persistent-session-id";
        when(authenticationService.userExists(EMAIL)).thenReturn(false);
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody(format("{ \"password\": \"%s\", \"email\": \"%s\" }", PASSWORD, EMAIL));
        event.setRequestContext(contextWithSourceIp("123.123.123.123"));
        event.setHeaders(Map.of(PersistentIdHelper.PERSISTENT_ID_HEADER_NAME, persistentIdValue));
        when(authenticationService.login(EMAIL, PASSWORD)).thenReturn(false);

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1010));

        verify(auditService)
                .submitAuditEvent(
                        AccountManagementAuditableEvent.ACCOUNT_MANAGEMENT_AUTHENTICATE_FAILURE,
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        EMAIL,
                        IP_ADDRESS,
                        AuditService.UNKNOWN,
                        persistentIdValue,
                        AuditService.RestrictedSection.empty);
    }
}
