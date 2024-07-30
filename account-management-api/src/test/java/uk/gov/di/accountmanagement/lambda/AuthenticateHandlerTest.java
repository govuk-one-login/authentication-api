package uk.gov.di.accountmanagement.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.accountmanagement.helpers.AuditHelper;
import uk.gov.di.audit.AuditContext;
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
import static uk.gov.di.accountmanagement.domain.AccountManagementAuditableEvent.ACCOUNT_MANAGEMENT_AUTHENTICATE;
import static uk.gov.di.accountmanagement.domain.AccountManagementAuditableEvent.ACCOUNT_MANAGEMENT_AUTHENTICATE_FAILURE;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.*;
import static uk.gov.di.authentication.sharedtest.helper.RequestEventHelper.contextWithSourceIp;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class AuthenticateHandlerTest {

    private static final String TXMA_ENCODED_HEADER_VALUE = "txma-test-value";
    private static final Map<String, String> headers =
            Map.of(
                    PersistentIdHelper.PERSISTENT_ID_HEADER_NAME,
                    PERSISTENT_SESSION_ID,
                    AuditHelper.TXMA_ENCODED_HEADER_NAME,
                    TXMA_ENCODED_HEADER_VALUE);
    private APIGatewayProxyRequestEvent event;
    private AuthenticateHandler handler;
    private final Context context = mock(Context.class);
    private final AuthenticationService authenticationService = mock(AuthenticationService.class);
    private final AuditService auditService = mock(AuditService.class);
    private final AuditContext auditContext =
            new AuditContext(
                    AuditService.UNKNOWN,
                    AuditService.UNKNOWN,
                    AuditService.UNKNOWN,
                    AuditService.UNKNOWN,
                    EMAIL,
                    IP_ADDRESS,
                    AuditService.UNKNOWN,
                    PERSISTENT_SESSION_ID,
                    Optional.of(TXMA_ENCODED_HEADER_VALUE));

    @BeforeEach
    public void setUp() {
        handler = new AuthenticateHandler(authenticationService, auditService);
        event = new APIGatewayProxyRequestEvent();
        event.setHeaders(headers);
        event.setRequestContext(contextWithSourceIp(IP_ADDRESS));
        //  pragma: allowlist nextline secret
        event.setBody(format("{ \"password\": \"%s\", \"email\": \"%s\" }", PASSWORD, EMAIL));
    }

    @Test
    public void shouldReturn204IfLoginIsSuccessful() {
        when(authenticationService.userExists(EMAIL)).thenReturn(true);
        when(authenticationService.login(EMAIL, PASSWORD)).thenReturn(true);
        when(authenticationService.getPhoneNumber(EMAIL))
                .thenReturn(Optional.of(UK_LANDLINE_NUMBER));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(204));

        verify(auditService).submitAuditEvent(ACCOUNT_MANAGEMENT_AUTHENTICATE, auditContext);
    }

    @Test
    public void shouldNotSendEncodedAuditDataIfHeaderNotPresent() {
        event.setHeaders(
                Map.of(PersistentIdHelper.PERSISTENT_ID_HEADER_NAME, PERSISTENT_SESSION_ID));
        when(authenticationService.userExists(EMAIL)).thenReturn(true);
        when(authenticationService.login(EMAIL, PASSWORD)).thenReturn(true);
        when(authenticationService.getPhoneNumber(EMAIL))
                .thenReturn(Optional.of(UK_LANDLINE_NUMBER));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(204));

        verify(auditService)
                .submitAuditEvent(
                        ACCOUNT_MANAGEMENT_AUTHENTICATE,
                        auditContext.withTxmaAuditEncoded(Optional.empty()));
    }

    @Test
    public void shouldReturn401IfUserHasInvalidCredentials() {
        when(authenticationService.userExists(EMAIL)).thenReturn(true);
        when(authenticationService.login(EMAIL, PASSWORD)).thenReturn(false);

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(401));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1008));

        verify(auditService)
                .submitAuditEvent(ACCOUNT_MANAGEMENT_AUTHENTICATE_FAILURE, auditContext);
    }

    @Test
    public void shouldReturn400IfAnyRequestParametersAreMissing() {
        //  pragma: allowlist nextline secret
        event.setBody(format("{ \"password\": \"%s\"}", PASSWORD));
        when(authenticationService.login(EMAIL, PASSWORD)).thenReturn(false);
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1001));

        verify(auditService)
                .submitAuditEvent(
                        ACCOUNT_MANAGEMENT_AUTHENTICATE_FAILURE,
                        auditContext.withEmail(AuditService.UNKNOWN));
    }

    @Test
    public void shouldReturn400IfUserDoesNotHaveAnAccount() {
        when(authenticationService.userExists(EMAIL)).thenReturn(false);
        when(authenticationService.login(EMAIL, PASSWORD)).thenReturn(false);

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1010));

        verify(auditService)
                .submitAuditEvent(ACCOUNT_MANAGEMENT_AUTHENTICATE_FAILURE, auditContext);
    }
}
