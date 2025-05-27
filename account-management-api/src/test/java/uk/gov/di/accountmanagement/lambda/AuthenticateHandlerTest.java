package uk.gov.di.accountmanagement.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.accountmanagement.helpers.AuditHelper;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.shared.entity.*;
import uk.gov.di.authentication.shared.exceptions.UnsuccessfulAccountInterventionsResponseException;
import uk.gov.di.authentication.shared.helpers.ClientSessionIdHelper;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.helpers.SaltHelper;
import uk.gov.di.authentication.shared.services.AccountInterventionsService;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.util.Map;
import java.util.Optional;

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.accountmanagement.domain.AccountManagementAuditableEvent.*;
import static uk.gov.di.authentication.sharedtest.helper.RequestEventHelper.contextWithSourceIp;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class AuthenticateHandlerTest {

    private static final String EMAIL = "computer-1";
    private static final String PASSWORD = "joe.bloggs@test.com";
    private static final String PHONE_NUMBER = "01234567890";
    private static final String IP_ADDRESS = "123.123.123.123";
    private static final String PERSISTENT_SESSION_ID = "some-persistent-session-id";
    private static final String SESSION_ID = "some-session-id";
    private static final String TXMA_ENCODED_HEADER_VALUE = "txma-test-value";
    private static final Map<String, String> headers =
            Map.of(
                    PersistentIdHelper.PERSISTENT_ID_HEADER_NAME,
                    PERSISTENT_SESSION_ID,
                    AuditHelper.TXMA_ENCODED_HEADER_NAME,
                    TXMA_ENCODED_HEADER_VALUE,
                    ClientSessionIdHelper.SESSION_ID_HEADER_NAME,
                    SESSION_ID);
    public static final UserProfile USER_PROFILE =
            new UserProfile().withSubjectID(new Subject().getValue());
    private APIGatewayProxyRequestEvent event;
    private AuthenticateHandler handler;
    private final Context context = mock(Context.class);
    private final AuthenticationService authenticationService = mock(AuthenticationService.class);
    private final AuditService auditService = mock(AuditService.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final AccountInterventionsService accountInterventionsService =
            mock(AccountInterventionsService.class);
    private final AuditContext auditContext =
            new AuditContext(
                    AuditService.UNKNOWN,
                    SESSION_ID,
                    AuditService.UNKNOWN,
                    AuditService.UNKNOWN,
                    EMAIL,
                    IP_ADDRESS,
                    AuditService.UNKNOWN,
                    PERSISTENT_SESSION_ID,
                    Optional.of(TXMA_ENCODED_HEADER_VALUE));
    private String clientSubjectId;

    @BeforeEach
    public void setUp() throws UnsuccessfulAccountInterventionsResponseException {
        when(configurationService.getInternalSectorUri()).thenReturn("https://test.account.gov.uk");
        when(configurationService.isAccountInterventionServiceCallInAuthenticateEnabled())
                .thenReturn(false);
        when(authenticationService.getOrGenerateSalt(USER_PROFILE))
                .thenReturn(SaltHelper.generateNewSalt());

        handler =
                new AuthenticateHandler(
                        authenticationService,
                        auditService,
                        configurationService,
                        accountInterventionsService);
        event = new APIGatewayProxyRequestEvent();
        event.setHeaders(headers);
        event.setRequestContext(contextWithSourceIp(IP_ADDRESS));
        event.setBody(format("{ \"password\": \"%s\", \"email\": \"%s\" }", PASSWORD, EMAIL));

        clientSubjectId =
                ClientSubjectHelper.getSubjectWithSectorIdentifier(
                                USER_PROFILE,
                                configurationService.getInternalSectorUri(),
                                authenticationService)
                        .getValue();

        when(accountInterventionsService.sendAccountInterventionsOutboundRequest(clientSubjectId))
                .thenReturn(
                        new AccountInterventionsInboundResponse(
                                new Intervention(1L), new State(false, false, false, false)));
    }

    @Test
    public void shouldReturn204IfLoginIsSuccessful() {
        when(authenticationService.getUserProfileByEmailMaybe(EMAIL))
                .thenReturn(Optional.of(USER_PROFILE));
        when(authenticationService.login(EMAIL, PASSWORD)).thenReturn(true);
        when(authenticationService.getPhoneNumber(EMAIL)).thenReturn(Optional.of(PHONE_NUMBER));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(204));

        verify(auditService)
                .submitAuditEvent(
                        AUTH_ACCOUNT_MANAGEMENT_AUTHENTICATE,
                        auditContext.withSubjectId(clientSubjectId));
    }

    @Test
    public void shouldNotSendEncodedAuditDataIfHeaderNotPresent() {
        event.setHeaders(
                Map.of(PersistentIdHelper.PERSISTENT_ID_HEADER_NAME, PERSISTENT_SESSION_ID));
        when(authenticationService.getUserProfileByEmailMaybe(EMAIL))
                .thenReturn(Optional.of(USER_PROFILE));
        when(authenticationService.login(EMAIL, PASSWORD)).thenReturn(true);
        when(authenticationService.getPhoneNumber(EMAIL)).thenReturn(Optional.of(PHONE_NUMBER));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(204));

        verify(auditService)
                .submitAuditEvent(
                        AUTH_ACCOUNT_MANAGEMENT_AUTHENTICATE,
                        auditContext
                                .withClientSessionId("unknown")
                                .withSubjectId(clientSubjectId)
                                .withTxmaAuditEncoded(Optional.empty()));
    }

    @Test
    public void shouldReturn401IfUserHasInvalidCredentials() {
        when(authenticationService.getUserProfileByEmailMaybe(EMAIL))
                .thenReturn(Optional.of(USER_PROFILE));
        when(authenticationService.login(EMAIL, PASSWORD)).thenReturn(false);

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(401));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1008));

        verify(auditService)
                .submitAuditEvent(
                        AUTH_ACCOUNT_MANAGEMENT_AUTHENTICATE_FAILURE,
                        auditContext.withSubjectId(clientSubjectId));
    }

    @Test
    public void shouldReturn400IfAnyRequestParametersAreMissing() {
        event.setBody(format("{ \"password\": \"%s\"}", PASSWORD));
        when(authenticationService.login(EMAIL, PASSWORD)).thenReturn(false);
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1001));

        verify(auditService)
                .submitAuditEvent(
                        AUTH_ACCOUNT_MANAGEMENT_AUTHENTICATE_FAILURE,
                        auditContext.withEmail(AuditService.UNKNOWN));
    }

    @Test
    public void shouldReturn400IfUserDoesNotHaveAnAccount() {
        when(authenticationService.getUserProfileByEmailMaybe(EMAIL)).thenReturn(Optional.empty());
        when(authenticationService.login(EMAIL, PASSWORD)).thenReturn(false);

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1010));

        verify(auditService)
                .submitAuditEvent(AUTH_ACCOUNT_MANAGEMENT_AUTHENTICATE_FAILURE, auditContext);
    }

    @Test
    public void shouldReturn403IfAisCallEnabledAndUserIsBlocked()
            throws UnsuccessfulAccountInterventionsResponseException {
        when(configurationService.isAccountInterventionServiceCallInAuthenticateEnabled())
                .thenReturn(true);
        when(authenticationService.getUserProfileByEmailMaybe(EMAIL))
                .thenReturn(Optional.of(USER_PROFILE));
        when(authenticationService.login(EMAIL, PASSWORD)).thenReturn(true);
        when(authenticationService.getPhoneNumber(EMAIL)).thenReturn(Optional.of(PHONE_NUMBER));

        when(accountInterventionsService.sendAccountInterventionsOutboundRequest(clientSubjectId))
                .thenReturn(
                        new AccountInterventionsInboundResponse(
                                new Intervention(1L), new State(true, false, false, false)));

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(403));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1084));

        verify(auditService)
                .submitAuditEvent(
                        AUTH_ACCOUNT_MANAGEMENT_AUTHENTICATE_INTERVENTION_FAILURE,
                        auditContext.withSubjectId(clientSubjectId));
    }

    @Test
    public void shouldReturn403IfIfAisCallEnabledAndUserIsSuspended()
            throws UnsuccessfulAccountInterventionsResponseException {
        when(configurationService.isAccountInterventionServiceCallInAuthenticateEnabled())
                .thenReturn(true);
        when(authenticationService.getUserProfileByEmailMaybe(EMAIL))
                .thenReturn(Optional.of(USER_PROFILE));
        when(authenticationService.login(EMAIL, PASSWORD)).thenReturn(true);
        when(authenticationService.getPhoneNumber(EMAIL)).thenReturn(Optional.of(PHONE_NUMBER));

        when(accountInterventionsService.sendAccountInterventionsOutboundRequest(clientSubjectId))
                .thenReturn(
                        new AccountInterventionsInboundResponse(
                                new Intervention(1L), new State(false, true, false, false)));

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(403));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1083));

        verify(auditService)
                .submitAuditEvent(
                        AUTH_ACCOUNT_MANAGEMENT_AUTHENTICATE_INTERVENTION_FAILURE,
                        auditContext.withSubjectId(clientSubjectId));
    }

    @Test
    public void shouldReturn204IfIfAisCallEnabledAndUserIsSuspendedWithPasswordReset()
            throws UnsuccessfulAccountInterventionsResponseException {
        when(configurationService.isAccountInterventionServiceCallInAuthenticateEnabled())
                .thenReturn(true);
        when(authenticationService.getUserProfileByEmailMaybe(EMAIL))
                .thenReturn(Optional.of(USER_PROFILE));
        when(authenticationService.login(EMAIL, PASSWORD)).thenReturn(true);
        when(authenticationService.getPhoneNumber(EMAIL)).thenReturn(Optional.of(PHONE_NUMBER));

        when(accountInterventionsService.sendAccountInterventionsOutboundRequest(clientSubjectId))
                .thenReturn(
                        new AccountInterventionsInboundResponse(
                                new Intervention(1L), new State(false, true, false, true)));

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(204));

        verify(auditService)
                .submitAuditEvent(
                        AUTH_ACCOUNT_MANAGEMENT_AUTHENTICATE,
                        auditContext.withSubjectId(clientSubjectId));
    }

    @Test
    public void shouldReturn204IfIfAisCallEnabledAndUserIsSuspendedWithReproveIdentity()
            throws UnsuccessfulAccountInterventionsResponseException {
        when(configurationService.isAccountInterventionServiceCallInAuthenticateEnabled())
                .thenReturn(true);
        when(authenticationService.getUserProfileByEmailMaybe(EMAIL))
                .thenReturn(Optional.of(USER_PROFILE));
        when(authenticationService.login(EMAIL, PASSWORD)).thenReturn(true);
        when(authenticationService.getPhoneNumber(EMAIL)).thenReturn(Optional.of(PHONE_NUMBER));

        when(accountInterventionsService.sendAccountInterventionsOutboundRequest(clientSubjectId))
                .thenReturn(
                        new AccountInterventionsInboundResponse(
                                new Intervention(1L), new State(false, true, true, false)));

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(204));

        verify(auditService)
                .submitAuditEvent(
                        AUTH_ACCOUNT_MANAGEMENT_AUTHENTICATE,
                        auditContext.withSubjectId(clientSubjectId));
    }

    @Test
    public void
            shouldReturn204IfIfAisCallEnabledAndUserIsSuspendedWithResetPasswordAndReproveIdentity()
                    throws UnsuccessfulAccountInterventionsResponseException {
        when(configurationService.isAccountInterventionServiceCallInAuthenticateEnabled())
                .thenReturn(true);
        when(authenticationService.getUserProfileByEmailMaybe(EMAIL))
                .thenReturn(Optional.of(USER_PROFILE));
        when(authenticationService.login(EMAIL, PASSWORD)).thenReturn(true);
        when(authenticationService.getPhoneNumber(EMAIL)).thenReturn(Optional.of(PHONE_NUMBER));

        when(accountInterventionsService.sendAccountInterventionsOutboundRequest(clientSubjectId))
                .thenReturn(
                        new AccountInterventionsInboundResponse(
                                new Intervention(1L), new State(false, true, true, true)));

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(204));

        verify(auditService)
                .submitAuditEvent(
                        AUTH_ACCOUNT_MANAGEMENT_AUTHENTICATE,
                        auditContext.withSubjectId(clientSubjectId));
    }

    @Test
    public void shouldReturn500IfIfAisCallEnabledTheCallFails()
            throws UnsuccessfulAccountInterventionsResponseException {
        when(configurationService.isAccountInterventionServiceCallInAuthenticateEnabled())
                .thenReturn(true);
        when(authenticationService.getUserProfileByEmailMaybe(EMAIL))
                .thenReturn(Optional.of(USER_PROFILE));
        when(authenticationService.login(EMAIL, PASSWORD)).thenReturn(true);
        when(authenticationService.getPhoneNumber(EMAIL)).thenReturn(Optional.of(PHONE_NUMBER));

        when(accountInterventionsService.sendAccountInterventionsOutboundRequest(clientSubjectId))
                .thenThrow(
                        new UnsuccessfulAccountInterventionsResponseException(
                                "Internal Server Error", 500));

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(500));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1055));

        verify(auditService)
                .submitAuditEvent(
                        AUTH_ACCOUNT_MANAGEMENT_AUTHENTICATE_FAILURE,
                        auditContext.withSubjectId(clientSubjectId));
    }
}
