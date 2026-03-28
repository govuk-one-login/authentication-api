package uk.gov.di.accountmanagement.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.accountmanagement.entity.ActionSource;
import uk.gov.di.accountmanagement.entity.TargetAction;
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

import java.util.ArrayList;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.accountmanagement.constants.AccountManagementConstants.AUDIT_EVENT_COMPONENT_ID_AUTH;
import static uk.gov.di.accountmanagement.domain.AccountManagementAuditableEvent.*;
import static uk.gov.di.authentication.shared.services.AuditService.MetadataPair.pair;
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
                    Optional.of(TXMA_ENCODED_HEADER_VALUE),
                    new ArrayList<>());
    private String clientSubjectId;

    @BeforeEach
    void setUp() throws UnsuccessfulAccountInterventionsResponseException {
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

    private static Stream<Arguments> targetActionAndSourceValues() {
        var targetActions =
                java.util.List.of(
                        "not-a-valid-target-action",
                        TargetAction.DELETE_ACCOUNT.getValue(),
                        TargetAction.UPDATE_EMAIL.getValue(),
                        TargetAction.UPDATE_PASSWORD.getValue(),
                        TargetAction.UPDATE_MFA.getValue());
        var actionSources =
                java.util.List.of(
                        "not-a-valid-action-source",
                        ActionSource.ACCOUNT_MANAGEMENT.getValue(),
                        ActionSource.ACCOUNT_COMPONENTS.getValue());
        return targetActions.stream()
                .flatMap(
                        target ->
                                actionSources.stream().map(source -> Arguments.of(target, source)));
    }

    @ParameterizedTest
    @MethodSource("targetActionAndSourceValues")
    void shouldReturn204IfLoginIsSuccessful(String targetActionValue, String actionSourceValue) {
        when(authenticationService.getUserProfileByEmailMaybe(EMAIL))
                .thenReturn(Optional.of(USER_PROFILE));
        when(authenticationService.login(EMAIL, PASSWORD)).thenReturn(true);
        when(authenticationService.getPhoneNumber(EMAIL)).thenReturn(Optional.of(PHONE_NUMBER));
        event.setBody(
                format(
                        "{ \"password\": \"%s\", \"email\": \"%s\", \"target_action\": \"%s\", \"action_source\": \"%s\" }",
                        PASSWORD, EMAIL, targetActionValue, actionSourceValue));

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(204));

        String expectedTargetActionAuditValue =
                "not-a-valid-target-action".equals(targetActionValue)
                        ? AuditService.UNKNOWN
                        : targetActionValue;
        String expectedActionSourceAuditValue =
                "not-a-valid-action-source".equals(actionSourceValue)
                        ? AuditService.UNKNOWN
                        : actionSourceValue;

        verify(auditService)
                .submitAuditEvent(
                        AUTH_ACCOUNT_MANAGEMENT_AUTHENTICATE,
                        auditContext.withSubjectId(clientSubjectId),
                        AUDIT_EVENT_COMPONENT_ID_AUTH,
                        pair("target_action", expectedTargetActionAuditValue),
                        pair("action_source", expectedActionSourceAuditValue));
    }

    @Test
    void shouldNotSendEncodedAuditDataIfHeaderNotPresent() {
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
                                .withTxmaAuditEncoded(Optional.empty()),
                        AUDIT_EVENT_COMPONENT_ID_AUTH,
                        pair("target_action", AuditService.UNKNOWN),
                        pair("action_source", AuditService.UNKNOWN));
    }

    @Test
    void shouldReturn401IfUserHasInvalidCredentials() {
        when(authenticationService.getUserProfileByEmailMaybe(EMAIL))
                .thenReturn(Optional.of(USER_PROFILE));
        when(authenticationService.login(EMAIL, PASSWORD)).thenReturn(false);

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(401));
        assertThat(result, hasJsonBody(ErrorResponse.INVALID_LOGIN_CREDS));

        verify(auditService)
                .submitAuditEvent(
                        AUTH_ACCOUNT_MANAGEMENT_AUTHENTICATE_FAILURE,
                        auditContext.withSubjectId(clientSubjectId),
                        AUDIT_EVENT_COMPONENT_ID_AUTH);
    }

    @Test
    void shouldReturn400IfAnyRequestParametersAreMissing() {
        event.setBody(format("{ \"password\": \"%s\"}", PASSWORD));
        when(authenticationService.login(EMAIL, PASSWORD)).thenReturn(false);
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.REQUEST_MISSING_PARAMS));

        verify(auditService)
                .submitAuditEvent(
                        AUTH_ACCOUNT_MANAGEMENT_AUTHENTICATE_FAILURE,
                        auditContext.withEmail(AuditService.UNKNOWN),
                        AUDIT_EVENT_COMPONENT_ID_AUTH);
    }

    @Test
    void shouldReturn400IfUserDoesNotHaveAnAccount() {
        when(authenticationService.getUserProfileByEmailMaybe(EMAIL)).thenReturn(Optional.empty());
        when(authenticationService.login(EMAIL, PASSWORD)).thenReturn(false);

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ACCT_DOES_NOT_EXIST));

        verify(auditService)
                .submitAuditEvent(
                        AUTH_ACCOUNT_MANAGEMENT_AUTHENTICATE_FAILURE,
                        auditContext,
                        AUDIT_EVENT_COMPONENT_ID_AUTH);
    }

    @Test
    void shouldReturn403IfAisCallEnabledAndUserIsBlocked()
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
        assertThat(result, hasJsonBody(ErrorResponse.ACCT_BLOCKED));

        verify(auditService)
                .submitAuditEvent(
                        AUTH_ACCOUNT_MANAGEMENT_AUTHENTICATE_INTERVENTION_FAILURE,
                        auditContext.withSubjectId(clientSubjectId),
                        AUDIT_EVENT_COMPONENT_ID_AUTH);
    }

    @Test
    void shouldReturn403IfIfAisCallEnabledAndUserIsSuspended()
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
        assertThat(result, hasJsonBody(ErrorResponse.ACCT_SUSPENDED));

        verify(auditService)
                .submitAuditEvent(
                        AUTH_ACCOUNT_MANAGEMENT_AUTHENTICATE_INTERVENTION_FAILURE,
                        auditContext.withSubjectId(clientSubjectId),
                        AUDIT_EVENT_COMPONENT_ID_AUTH);
    }

    private static Stream<Arguments> suspendedUserStates() {
        return Stream.of(
                Arguments.of(true, false), // password reset only
                Arguments.of(false, true), // reprove identity only
                Arguments.of(true, true) // both password reset and reprove identity
                );
    }

    @ParameterizedTest
    @MethodSource("suspendedUserStates")
    void shouldReturn204IfAisCallEnabledAndUserIsSuspendedWithInterventions(
            boolean resetPassword, boolean reproveIdentity)
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
                                new Intervention(1L),
                                new State(false, true, reproveIdentity, resetPassword)));

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(204));

        verify(auditService)
                .submitAuditEvent(
                        AUTH_ACCOUNT_MANAGEMENT_AUTHENTICATE,
                        auditContext.withSubjectId(clientSubjectId),
                        AUDIT_EVENT_COMPONENT_ID_AUTH,
                        pair("target_action", AuditService.UNKNOWN),
                        pair("action_source", AuditService.UNKNOWN));
    }

    @Test
    void shouldReturn500IfIfAisCallEnabledTheCallFails()
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
        assertThat(result, hasJsonBody(ErrorResponse.ACCT_INTERVENTIONS_UNEXPECTED_ERROR));

        verify(auditService)
                .submitAuditEvent(
                        AUTH_ACCOUNT_MANAGEMENT_AUTHENTICATE_FAILURE,
                        auditContext.withSubjectId(clientSubjectId),
                        AUDIT_EVENT_COMPONENT_ID_AUTH);
    }
}
