package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.frontendapi.helpers.ApiGatewayProxyRequestHelper;
import uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables;
import uk.gov.di.authentication.frontendapi.services.JwtService;
import uk.gov.di.authentication.frontendapi.services.MfaResetIPVAuthorizationService;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.KmsConnectionService;
import uk.gov.di.authentication.shared.services.SessionService;
import uk.gov.di.authentication.shared.services.TokenService;
import uk.gov.di.authentication.shared.state.UserContext;

import java.util.Map;
import java.util.Optional;

import static java.lang.String.format;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.CLIENT_SESSION_ID;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.DI_PERSISTENT_SESSION_ID;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.EMAIL;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.ENCODED_DEVICE_DETAILS;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.INTERNAL_SUBJECT_ID;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.IP_ADDRESS;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.SESSION_ID;

class MfaResetAuthorizeHandlerTest {
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final MfaResetIPVAuthorizationService mfaResetIPVAuthorizationService =
            mock(MfaResetIPVAuthorizationService.class);
    private final AuthenticationService authenticationService = mock(AuthenticationService.class);
    private final ClientSessionService clientSessionService = mock(ClientSessionService.class);
    private final ClientService clientService = mock(ClientService.class);
    private final Context context = mock(Context.class);
    private final SessionService sessionService = mock(SessionService.class);
    private final UserContext userContext = mock(UserContext.class);
    private final Session session = mock(Session.class);
    private final AuditContext testAuditContext =
            new AuditContext(
                    AuditService.UNKNOWN,
                    CLIENT_SESSION_ID,
                    SESSION_ID,
                    AuditService.UNKNOWN,
                    EMAIL,
                    IP_ADDRESS,
                    AuditService.UNKNOWN,
                    DI_PERSISTENT_SESSION_ID,
                    Optional.of(ENCODED_DEVICE_DETAILS));
    private final APIGatewayProxyRequestEvent TEST_INVOKE_EVENT =
            ApiGatewayProxyRequestHelper.apiRequestEventWithHeadersAndBody(
                    CommonTestVariables.VALID_HEADERS,
                    format("{ \"email\": \"%s\" }", EMAIL.toUpperCase()));
    private MfaResetAuthorizeHandler handler;

    @BeforeEach
    void testSetup() {
        mock(SessionService.class);
        mock(KmsConnectionService.class);
        mock(JwtService.class);
        mock(TokenService.class);
        mock(CloudwatchMetricsService.class);
        mock(AuditService.class);
        when(userContext.getSession()).thenReturn(new Session(SESSION_ID));
        when(userContext.getClientSessionId()).thenReturn(CLIENT_SESSION_ID);
        when(session.getInternalCommonSubjectIdentifier()).thenReturn(INTERNAL_SUBJECT_ID);
        when(sessionService.getSessionFromRequestHeaders(anyMap()))
                .thenReturn(Optional.of(session));
        when(session.getSessionId()).thenReturn(SESSION_ID);
        handler =
                new MfaResetAuthorizeHandler(
                        configurationService,
                        sessionService,
                        clientSessionService,
                        clientService,
                        authenticationService,
                        mfaResetIPVAuthorizationService);
    }

    @Test
    void returnsResultOfSendMfaResetRequestToIPV() {

        String TEST_REDIRECT_URI = "https://some.uri.gov.uk/authorize";
        Map<String, String> expectedHeaders = Map.of("Location", TEST_REDIRECT_URI);
        when(mfaResetIPVAuthorizationService.sendMfaResetRequestToIPV(
                        any(Subject.class),
                        anyString(),
                        any(Session.class),
                        any(AuditContext.class)))
                .thenReturn(
                        ApiGatewayProxyRequestHelper.apiResponseEvent(302, "", expectedHeaders));

        APIGatewayProxyResponseEvent response = handler.handleRequest(TEST_INVOKE_EVENT, context);

        verify(mfaResetIPVAuthorizationService)
                .sendMfaResetRequestToIPV(
                        new Subject(INTERNAL_SUBJECT_ID),
                        CLIENT_SESSION_ID,
                        session,
                        testAuditContext);
        assertEquals(302, response.getStatusCode());
        assertEquals("", response.getBody());
        assertEquals(expectedHeaders, response.getHeaders());
    }

    @Test
    void returnsA500WhenSendMfaResetRequestToIPVThrows() {
        when(mfaResetIPVAuthorizationService.sendMfaResetRequestToIPV(
                        any(Subject.class),
                        anyString(),
                        any(Session.class),
                        any(AuditContext.class)))
                .thenThrow(new RuntimeException("SomeError"));

        APIGatewayProxyResponseEvent response = handler.handleRequest(TEST_INVOKE_EVENT, context);

        verify(mfaResetIPVAuthorizationService)
                .sendMfaResetRequestToIPV(
                        new Subject(INTERNAL_SUBJECT_ID),
                        CLIENT_SESSION_ID,
                        session,
                        testAuditContext);
        assertEquals(500, response.getStatusCode());
        assertEquals("", response.getBody());
    }
}
