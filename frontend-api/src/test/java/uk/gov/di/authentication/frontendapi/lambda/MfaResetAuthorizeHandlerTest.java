package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.frontendapi.entity.MfaResetResponse;
import uk.gov.di.authentication.frontendapi.exceptions.IPVReverificationServiceException;
import uk.gov.di.authentication.frontendapi.exceptions.JwtServiceException;
import uk.gov.di.authentication.frontendapi.helpers.ApiGatewayProxyRequestHelper;
import uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables;
import uk.gov.di.authentication.frontendapi.services.IPVReverificationService;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthSessionService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.IDReverificationStateService;
import uk.gov.di.authentication.shared.services.SerializationService;
import uk.gov.di.authentication.shared.services.SessionService;
import uk.gov.di.authentication.shared.state.UserContext;

import java.util.Optional;

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_REVERIFY_AUTHORISATION_REQUESTED;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.CLIENT_SESSION_ID;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.DI_PERSISTENT_SESSION_ID;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.EMAIL;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.ENCODED_DEVICE_DETAILS;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.INTERNAL_COMMON_SUBJECT_ID;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.IP_ADDRESS;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.SESSION_ID;
import static uk.gov.di.authentication.shared.entity.ErrorResponse.ERROR_1060;
import static uk.gov.di.authentication.shared.services.AuditService.MetadataPair.pair;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class MfaResetAuthorizeHandlerTest {
    private static final SerializationService objectMapper = SerializationService.getInstance();
    private static final ConfigurationService configurationService =
            mock(ConfigurationService.class);
    private final IPVReverificationService ipvReverificationService =
            mock(IPVReverificationService.class);
    private static final AuthenticationService authenticationService =
            mock(AuthenticationService.class);
    private static final ClientSessionService clientSessionService =
            mock(ClientSessionService.class);
    private static final ClientService clientService = mock(ClientService.class);
    private static final Context context = mock(Context.class);
    private static final SessionService sessionService = mock(SessionService.class);
    private static final UserContext userContext = mock(UserContext.class);
    private static final Session session =
            new Session().setInternalCommonSubjectIdentifier(INTERNAL_COMMON_SUBJECT_ID);
    private static final AuditService auditService = mock(AuditService.class);
    private static final CloudwatchMetricsService cloudwatchMetricsService =
            mock(CloudwatchMetricsService.class);
    private static final IDReverificationStateService idReverificationStateService =
            mock(IDReverificationStateService.class);
    private static final AuthSessionService authSessionService = mock(AuthSessionService.class);

    private static final AuditContext testAuditContext =
            new AuditContext(
                    AuditService.UNKNOWN,
                    CLIENT_SESSION_ID,
                    SESSION_ID,
                    INTERNAL_COMMON_SUBJECT_ID,
                    EMAIL,
                    IP_ADDRESS,
                    AuditService.UNKNOWN,
                    DI_PERSISTENT_SESSION_ID,
                    Optional.of(ENCODED_DEVICE_DETAILS));
    private static final String ORCHESTRATION_STATE = "ORCHESTRATION_STATE";
    private static final APIGatewayProxyRequestEvent TEST_INVOKE_EVENT =
            ApiGatewayProxyRequestHelper.apiRequestEventWithHeadersAndBody(
                    CommonTestVariables.VALID_HEADERS,
                    format(
                            "{ \"email\": \"%s\", \"orchestrationRedirectUrl\": \"%s\" }",
                            EMAIL, ORCHESTRATION_STATE));
    private static final AuthSessionItem authSession =
            new AuthSessionItem()
                    .withSessionId(SESSION_ID)
                    .withInternalCommonSubjectId(INTERNAL_COMMON_SUBJECT_ID);
    private static MfaResetAuthorizeHandler handler;

    @BeforeAll
    static void globalSetup() {
        when(userContext.getSession()).thenReturn(new Session(SESSION_ID));
        when(userContext.getClientSessionId()).thenReturn(CLIENT_SESSION_ID);
        when(session.getInternalCommonSubjectIdentifier()).thenReturn(INTERNAL_COMMON_SUBJECT_ID);
        when(sessionService.getSessionFromRequestHeaders(anyMap()))
                .thenReturn(Optional.of(session));
        when(authSessionService.getSessionFromRequestHeaders(anyMap()))
                .thenReturn(Optional.of(authSession));
    }

    @BeforeEach
    void testSetup() {
        handler =
                new MfaResetAuthorizeHandler(
                        configurationService,
                        sessionService,
                        clientSessionService,
                        clientService,
                        authenticationService,
                        ipvReverificationService,
                        auditService,
                        cloudwatchMetricsService,
                        idReverificationStateService,
                        authSessionService);
    }

    @Test
    void returnsA200WithRedirectUriInBody() {
        final String TEST_REDIRECT_URI = "https://some.uri.gov.uk/authorize?request=x.y.z";
        String expectedBody =
                objectMapper.writeValueAsString(new MfaResetResponse(TEST_REDIRECT_URI));
        when(ipvReverificationService.buildIpvReverificationRedirectUri(
                        eq(new Subject(INTERNAL_COMMON_SUBJECT_ID)), eq(CLIENT_SESSION_ID), any()))
                .thenReturn(TEST_REDIRECT_URI);

        APIGatewayProxyResponseEvent response = handler.handleRequest(TEST_INVOKE_EVENT, context);

        verify(auditService)
                .submitAuditEvent(
                        AUTH_REVERIFY_AUTHORISATION_REQUESTED,
                        testAuditContext,
                        pair("rpPairwiseId", AuditService.UNKNOWN),
                        pair("journey-type", JourneyType.ACCOUNT_RECOVERY.getValue()));
        verify(cloudwatchMetricsService).incrementMfaResetHandoffCount();

        assertThat(response, hasStatus(200));
        assertThat(response, hasBody(expectedBody));
    }

    @Test
    void storesTheStateValuesForCrossBrowserIssue() {
        handler.handleRequest(TEST_INVOKE_EVENT, context);

        ArgumentCaptor<State> authenticationStateCaptor = ArgumentCaptor.forClass(State.class);
        verify(ipvReverificationService)
                .buildIpvReverificationRedirectUri(
                        any(), any(), authenticationStateCaptor.capture());
        verify(idReverificationStateService)
                .store(
                        authenticationStateCaptor.getValue().getValue(),
                        ORCHESTRATION_STATE,
                        CLIENT_SESSION_ID);
    }

    @Test
    void returnsA500WithErrorMessageWhenServiceThrowsJwtServiceException() {
        when(ipvReverificationService.buildIpvReverificationRedirectUri(
                        eq(new Subject(INTERNAL_COMMON_SUBJECT_ID)), eq(CLIENT_SESSION_ID), any()))
                .thenThrow(new JwtServiceException("SomeError"));

        APIGatewayProxyResponseEvent response = handler.handleRequest(TEST_INVOKE_EVENT, context);

        assertThat(response, hasStatus(500));
        assertThat(response, hasBody(ERROR_1060.getMessage()));
    }

    @Test
    void returns500WithErrorMessageWhenIpvReverificationServiceExceptionIsThrown() {
        when(ipvReverificationService.buildIpvReverificationRedirectUri(
                        eq(new Subject(INTERNAL_COMMON_SUBJECT_ID)), eq(CLIENT_SESSION_ID), any()))
                .thenThrow(new IPVReverificationServiceException("SomeError"));

        APIGatewayProxyResponseEvent response = handler.handleRequest(TEST_INVOKE_EVENT, context);

        assertThat(response, hasStatus(500));
        assertThat(response, hasBody(ERROR_1060.getMessage()));
    }
}
