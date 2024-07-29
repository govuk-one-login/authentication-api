package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.frontendapi.entity.MfaResetResponse;
import uk.gov.di.authentication.frontendapi.exceptions.JwtServiceException;
import uk.gov.di.authentication.frontendapi.helpers.ApiGatewayProxyRequestHelper;
import uk.gov.di.authentication.frontendapi.services.MfaResetIPVAuthorizationService;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.SerializationService;
import uk.gov.di.authentication.shared.services.SessionService;
import uk.gov.di.authentication.shared.state.UserContext;
import uk.gov.di.authentication.sharedtest.helper.CommonTestVariables;

import java.util.Optional;

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.shared.entity.ErrorResponse.ERROR_1060;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.CLIENT_SESSION_ID;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.COMMON_SUBJECT_ID;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.EMAIL;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.ENCODED_DEVICE_DETAILS;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.IP_ADDRESS;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.PERSISTENT_SESSION_ID;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.SESSION_ID;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class MfaResetAuthorizeHandlerTest {
    private static final SerializationService objectMapper = SerializationService.getInstance();
    private static final ConfigurationService configurationService =
            mock(ConfigurationService.class);
    private final MfaResetIPVAuthorizationService mfaResetIPVAuthorizationService =
            mock(MfaResetIPVAuthorizationService.class);
    private static final AuthenticationService authenticationService =
            mock(AuthenticationService.class);
    private static final ClientSessionService clientSessionService =
            mock(ClientSessionService.class);
    private static final ClientService clientService = mock(ClientService.class);
    private static final Context context = mock(Context.class);
    private static final SessionService sessionService = mock(SessionService.class);
    private static final UserContext userContext = mock(UserContext.class);
    private static final Session session = mock(Session.class);
    private static final AuditContext testAuditContext =
            new AuditContext(
                    AuditService.UNKNOWN,
                    CLIENT_SESSION_ID,
                    SESSION_ID,
                    AuditService.UNKNOWN,
                    EMAIL,
                    IP_ADDRESS,
                    AuditService.UNKNOWN,
                    PERSISTENT_SESSION_ID,
                    Optional.of(ENCODED_DEVICE_DETAILS));
    private static final APIGatewayProxyRequestEvent TEST_INVOKE_EVENT =
            ApiGatewayProxyRequestHelper.apiRequestEventWithHeadersAndBody(
                    CommonTestVariables.VALID_HEADERS, format("{ \"email\": \"%s\" }", EMAIL));
    private static MfaResetAuthorizeHandler handler;

    @BeforeAll
    static void globalSetup() {
        when(userContext.getSession()).thenReturn(new Session(SESSION_ID));
        when(userContext.getClientSessionId()).thenReturn(CLIENT_SESSION_ID);
        when(session.getInternalCommonSubjectIdentifier()).thenReturn(COMMON_SUBJECT_ID);
        when(sessionService.getSessionFromRequestHeaders(anyMap()))
                .thenReturn(Optional.of(session));
        when(session.getSessionId()).thenReturn(SESSION_ID);
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
                        mfaResetIPVAuthorizationService);
    }

    @Test
    void returnsA200WithRedirectUriInBody() throws Json.JsonException {
        final String TEST_REDIRECT_URI = "https://some.uri.gov.uk/authorize";
        String expectedBody =
                objectMapper.writeValueAsString(new MfaResetResponse(TEST_REDIRECT_URI));
        when(mfaResetIPVAuthorizationService.buildMfaResetIpvRedirectRequest(
                        any(Subject.class),
                        anyString(),
                        any(Session.class),
                        any(AuditContext.class)))
                .thenReturn(ApiGatewayProxyRequestHelper.apiResponseEvent(200, expectedBody, null));

        APIGatewayProxyResponseEvent response = handler.handleRequest(TEST_INVOKE_EVENT, context);

        verify(mfaResetIPVAuthorizationService)
                .buildMfaResetIpvRedirectRequest(
                        new Subject(COMMON_SUBJECT_ID),
                        CLIENT_SESSION_ID,
                        session,
                        testAuditContext);
        assertThat(response, hasStatus(200));
        assertThat(response, hasBody(expectedBody));
        assertNull(response.getHeaders());
    }

    @Test
    void throwsWhenThereIsAParseException() throws Json.JsonException {
        when(mfaResetIPVAuthorizationService.buildMfaResetIpvRedirectRequest(
                        any(Subject.class),
                        anyString(),
                        any(Session.class),
                        any(AuditContext.class)))
                .thenThrow(new Json.JsonException("SomeError"));

        assertThrows(
                RuntimeException.class, () -> handler.handleRequest(TEST_INVOKE_EVENT, context));

        verify(mfaResetIPVAuthorizationService)
                .buildMfaResetIpvRedirectRequest(
                        new Subject(COMMON_SUBJECT_ID),
                        CLIENT_SESSION_ID,
                        session,
                        testAuditContext);
    }

    @Test
    void returnsA500WithErrorMessageWhenServiceThrowsJwtServiceException()
            throws Json.JsonException {
        when(mfaResetIPVAuthorizationService.buildMfaResetIpvRedirectRequest(
                        any(Subject.class),
                        anyString(),
                        any(Session.class),
                        any(AuditContext.class)))
                .thenThrow(new JwtServiceException("SomeError"));

        APIGatewayProxyResponseEvent response = handler.handleRequest(TEST_INVOKE_EVENT, context);

        verify(mfaResetIPVAuthorizationService)
                .buildMfaResetIpvRedirectRequest(
                        new Subject(COMMON_SUBJECT_ID),
                        CLIENT_SESSION_ID,
                        session,
                        testAuditContext);
        assertThat(response, hasStatus(500));
        assertThat(response, hasBody(ERROR_1060.getMessage()));
    }
}
