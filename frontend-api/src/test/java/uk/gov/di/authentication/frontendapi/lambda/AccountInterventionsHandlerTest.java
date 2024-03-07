package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent;
import uk.gov.di.authentication.frontendapi.entity.AccountInterventionsInboundResponse;
import uk.gov.di.authentication.frontendapi.entity.AccountInterventionsRequest;
import uk.gov.di.authentication.frontendapi.entity.AccountInterventionsResponse;
import uk.gov.di.authentication.frontendapi.entity.Intervention;
import uk.gov.di.authentication.frontendapi.entity.State;
import uk.gov.di.authentication.frontendapi.services.AccountInterventionsService;
import uk.gov.di.authentication.shared.entity.ClientSession;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.entity.VectorOfTrust;
import uk.gov.di.authentication.shared.exceptions.UnsuccessfulAccountInterventionsResponseException;
import uk.gov.di.authentication.shared.helpers.IdGenerator;
import uk.gov.di.authentication.shared.helpers.SaltHelper;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.*;
import uk.gov.di.authentication.shared.state.UserContext;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

public class AccountInterventionsHandlerTest {
    private static final String TEST_CLIENT_ID = "test_client_id";
    private static final String TEST_CLIENT_NAME = "test_client_name";
    private static final String TEST_SESSION_ID = "test-session-id";
    private static final String TEST_CLIENT_SESSION_ID = "test-client-session-id";
    private static final String TEST_PERSISTENT_SESSION_ID = "test-persistent-session-id";
    private static final String TEST_INTERNAL_SUBJECT_ID = "test-internal-subject-id";
    private static final String TEST_IP_ADDRESS = "123.123.123.123";
    private static final String TEST_EMAIL_ADDRESS = "test@test.com";
    private static final String TEST_SUBJECT_ID = "subject-id";
    private static final String INTERNAL_SECTOR_URI = "https://test.account.gov.uk";
    private static final String TEST_ENVIRONMENT = "test-environment";
    private static final byte[] SALT = SaltHelper.generateNewSalt();

    private AccountInterventionsHandler handler;
    private final Context context = mock(Context.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final SessionService sessionService = mock(SessionService.class);
    private final ClientSessionService clientSessionService = mock(ClientSessionService.class);
    private final AuthenticationService authenticationService = mock(AuthenticationService.class);
    private final AuditService auditService = mock(AuditService.class);
    private final UserContext userContext = mock(UserContext.class);
    private final AccountInterventionsService accountInterventionsService =
            mock(AccountInterventionsService.class);
    private final ClientService clientService = mock(ClientService.class);
    private final CloudwatchMetricsService cloudwatchMetricsService =
            mock(CloudwatchMetricsService.class);
    private static final ClientSession clientSession = getClientSession();
    private final Session session =
            new Session(IdGenerator.generate())
                    .setEmailAddress(TEST_EMAIL_ADDRESS)
                    .setSessionId(TEST_SESSION_ID)
                    .setInternalCommonSubjectIdentifier(TEST_INTERNAL_SUBJECT_ID);
    private static final Json objectMapper = SerializationService.getInstance();

    @BeforeEach
    void setUp() throws URISyntaxException {
        when(context.getAwsRequestId()).thenReturn("aws-session-id");
        when(sessionService.getSessionFromRequestHeaders(anyMap()))
                .thenReturn(Optional.of(session));
        UserProfile userProfile = generateUserProfile();
        when(authenticationService.getUserProfileByEmailMaybe(TEST_EMAIL_ADDRESS))
                .thenReturn(Optional.of(userProfile));
        when(configurationService.accountInterventionsServiceActionEnabled()).thenReturn(true);
        when(configurationService.isAccountInterventionServiceCallEnabled()).thenReturn(true);
        when(configurationService.getInternalSectorUri()).thenReturn(INTERNAL_SECTOR_URI);
        when(authenticationService.getOrGenerateSalt(any(UserProfile.class))).thenReturn(SALT);
        when(configurationService.getAccountInterventionServiceURI())
                .thenReturn(new URI("https://account-interventions.gov.uk/v1"));
        when(userContext.getSession()).thenReturn(session);
        when(userContext.getClientSession()).thenReturn(clientSession);
        when(userContext.getClientId()).thenReturn(TEST_CLIENT_ID);
        when(userContext.getClientSessionId()).thenReturn(TEST_CLIENT_SESSION_ID);
        when(configurationService.getAccountInterventionsErrorMetricName())
                .thenReturn("AISException");
        when(configurationService.getEnvironment()).thenReturn(TEST_ENVIRONMENT);
        handler =
                new AccountInterventionsHandler(
                        configurationService,
                        sessionService,
                        clientSessionService,
                        clientService,
                        authenticationService,
                        accountInterventionsService,
                        auditService,
                        cloudwatchMetricsService);
    }

    @Test
    void shouldReturnError400ResponseWhenAccountInterventionsRequestHasNoValidSessionId()
            throws Json.JsonException {
        var event = new APIGatewayProxyRequestEvent();
        var result = handler.handleRequest(event, context);
        assertThat(result, hasStatus(400));
        assertThat(result, hasBody(objectMapper.writeValueAsString(ErrorResponse.ERROR_1000)));
    }

    @Test
    void shouldReturnError400ResponseWhenAccountInterventionsRequestHasNoEmail()
            throws Json.JsonException {
        var event = new APIGatewayProxyRequestEvent();
        event.setHeaders(getHeaders());
        var result = handler.handleRequest(event, context);
        assertThat(result, hasStatus(400));
        assertThat(result, hasBody(objectMapper.writeValueAsString(ErrorResponse.ERROR_1001)));
    }

    @Test
    void shouldReturnErrorResponseWhenUserDoesNotExists() throws Json.JsonException {
        when(authenticationService.getUserProfileByEmailMaybe(anyString()))
                .thenReturn(Optional.empty());
        var result = handler.handleRequest(apiRequestEventWithEmail(TEST_EMAIL_ADDRESS), context);
        assertThat(result, hasStatus(400));
        assertThat(result, hasBody(objectMapper.writeValueAsString(ErrorResponse.ERROR_1049)));
    }

    @ParameterizedTest
    @MethodSource("httpErrorCodesAndAssociatedResponses")
    void shouldReturnErrorResponseWithGivenHttpStatusCode(
            int httpCode, ErrorResponse expectedErrorResponse)
            throws Json.JsonException, UnsuccessfulAccountInterventionsResponseException {
        when(configurationService.abortOnAccountInterventionsErrorResponse()).thenReturn(true);
        when(authenticationService.getUserProfileByEmailMaybe(anyString()))
                .thenReturn(Optional.of(generateUserProfile()));
        when(accountInterventionsService.sendAccountInterventionsOutboundRequest(any()))
                .thenThrow(
                        new UnsuccessfulAccountInterventionsResponseException(
                                "Unspecified Error", httpCode));
        var result = handler.handleRequest(apiRequestEventWithEmail(TEST_EMAIL_ADDRESS), context);
        assertThat(result, hasStatus(httpCode));
        assertThat(result, hasBody(objectMapper.writeValueAsString(expectedErrorResponse)));
    }

    @Test
    void
            shouldReturn200AndDefaultAccountInterventionsResponseWhenAccountInterventionsRequestUnsuccessfulAndAbortOnErrorIsFalse()
                    throws Json.JsonException, UnsuccessfulAccountInterventionsResponseException {
        when(configurationService.abortOnAccountInterventionsErrorResponse()).thenReturn(false);
        when(authenticationService.getUserProfileByEmailMaybe(anyString()))
                .thenReturn(Optional.of(generateUserProfile()));
        when(accountInterventionsService.sendAccountInterventionsOutboundRequest(any()))
                .thenThrow(
                        new UnsuccessfulAccountInterventionsResponseException(
                                "Any 4xx/5xx error valid here", 404));
        var result = handler.handleRequest(apiRequestEventWithEmail(TEST_EMAIL_ADDRESS), context);
        assertThat(result, hasStatus(200));
        assertEquals(
                result.getBody(),
                String.format(
                        "{\"passwordResetRequired\":%b,\"blocked\":%b,\"temporarilySuspended\":%b}",
                        false, false, false));
    }

    @Test
    void
            shouldReturn200AndDefaultAccountInterventionsResponseWhenAccountInterventionsRequestUnsuccessfulAndAccountInterventionsServiceActionDisabled()
                    throws UnsuccessfulAccountInterventionsResponseException {
        when(configurationService.abortOnAccountInterventionsErrorResponse()).thenReturn(true);
        when(configurationService.accountInterventionsServiceActionEnabled()).thenReturn(false);
        when(authenticationService.getUserProfileByEmailMaybe(anyString()))
                .thenReturn(Optional.of(generateUserProfile()));
        when(accountInterventionsService.sendAccountInterventionsOutboundRequest(any()))
                .thenThrow(
                        new UnsuccessfulAccountInterventionsResponseException(
                                "Any 4xx/5xx error valid here", 404));
        var result = handler.handleRequest(apiRequestEventWithEmail(TEST_EMAIL_ADDRESS), context);
        assertThat(result, hasStatus(200));
        assertEquals(
                result.getBody(),
                String.format(
                        "{\"passwordResetRequired\":%b,\"blocked\":%b,\"temporarilySuspended\":%b}",
                        false, false, false));
    }

    @Test
    void
            shouldReturn200AndDefaultAccountInterventionsResponseWhenAccountInterventionsServiceActionDisabledAndAccountHasInterventions()
                    throws UnsuccessfulAccountInterventionsResponseException {
        when(configurationService.accountInterventionsServiceActionEnabled()).thenReturn(false);
        when(authenticationService.getUserProfileByEmailMaybe(anyString()))
                .thenReturn(Optional.of(generateUserProfile()));
        when(accountInterventionsService.sendAccountInterventionsOutboundRequest(any()))
                .thenReturn(generateAccountInterventionResponse(true, true, true, true));
        var result = handler.handleRequest(apiRequestEventWithEmail(TEST_EMAIL_ADDRESS), context);
        assertThat(result, hasStatus(200));
        assertEquals(
                result.getBody(),
                String.format(
                        "{\"passwordResetRequired\":%b,\"blocked\":%b,\"temporarilySuspended\":%b}",
                        false, false, false));
    }

    @Test
    void shouldReturn200NotCallAccountInterventionsServiceWhenCallIsDiabled()
            throws UnsuccessfulAccountInterventionsResponseException {
        when(configurationService.isAccountInterventionServiceCallEnabled()).thenReturn(false);
        var result = handler.handleRequest(apiRequestEventWithEmail(TEST_EMAIL_ADDRESS), context);

        verify(accountInterventionsService, never()).sendAccountInterventionsOutboundRequest(any());
        assertThat(result, hasStatus(200));
        assertEquals(
                result.getBody(),
                String.format(
                        "{\"passwordResetRequired\":%b,\"blocked\":%b,\"temporarilySuspended\":%b}",
                        false, false, false));
    }

    static Stream<Arguments> accountInterventionResponseParameters() {
        return Stream.of(
                Arguments.of(false, false, false, false, FrontendAuditableEvent.NO_INTERVENTION),
                Arguments.of(false, true, true, false, FrontendAuditableEvent.NO_INTERVENTION),
                Arguments.of(
                        true,
                        false,
                        false,
                        false,
                        FrontendAuditableEvent.PERMANENTLY_BLOCKED_INTERVENTION),
                Arguments.of(
                        false,
                        true,
                        false,
                        false,
                        FrontendAuditableEvent.TEMP_SUSPENDED_INTERVENTION),
                Arguments.of(
                        false,
                        true,
                        false,
                        true,
                        FrontendAuditableEvent.PASSWORD_RESET_INTERVENTION),
                Arguments.of(
                        false,
                        true,
                        true,
                        true,
                        FrontendAuditableEvent.PASSWORD_RESET_INTERVENTION));
    }

    @ParameterizedTest
    @MethodSource("accountInterventionResponseParameters")
    void shouldReturn200ForSuccessfulRequestAndSubmitAppropriateAuditEvents(
            boolean blocked,
            boolean suspended,
            boolean reproveIdentity,
            boolean resetPassword,
            FrontendAuditableEvent expectedEvent)
            throws UnsuccessfulAccountInterventionsResponseException, Json.JsonException {
        var event = apiRequestEventWithEmail(TEST_EMAIL_ADDRESS);
        when(authenticationService.getUserProfileByEmailMaybe(anyString()))
                .thenReturn(Optional.of(generateUserProfile()));
        when(accountInterventionsService.sendAccountInterventionsOutboundRequest(any()))
                .thenReturn(
                        generateAccountInterventionResponse(
                                blocked, suspended, reproveIdentity, resetPassword));
        var result =
                handler.handleRequestWithUserContext(
                        event, context, new AccountInterventionsRequest("test"), userContext);
        assertThat(result, hasStatus(200));

        var accountInterventionsResponse =
                new AccountInterventionsResponse(resetPassword, blocked, suspended);
        assertThat(
                result,
                hasBody(objectMapper.writeValueAsStringCamelCase(accountInterventionsResponse)));
        assertEquals(
                result.getBody(),
                String.format(
                        "{\"passwordResetRequired\":%b,\"blocked\":%b,\"temporarilySuspended\":%b}",
                        resetPassword, blocked, suspended));
        verify(auditService)
                .submitAuditEvent(
                        expectedEvent,
                        TEST_CLIENT_SESSION_ID,
                        TEST_SESSION_ID,
                        TEST_CLIENT_ID,
                        TEST_INTERNAL_SUBJECT_ID,
                        TEST_EMAIL_ADDRESS,
                        TEST_IP_ADDRESS,
                        AuditService.UNKNOWN,
                        TEST_PERSISTENT_SESSION_ID);
    }

    private UserProfile generateUserProfile() {
        return new UserProfile()
                .withEmail(TEST_EMAIL_ADDRESS)
                .withEmailVerified(true)
                .withPhoneNumberVerified(true)
                .withPublicSubjectID(new Subject().getValue())
                .withSubjectID(TEST_SUBJECT_ID);
    }

    private AccountInterventionsInboundResponse generateAccountInterventionResponse(
            boolean blocked, boolean suspended, boolean reproveIdentity, boolean resetPassword) {
        return new AccountInterventionsInboundResponse(
                new Intervention(
                        "1696969322935",
                        "1696869005821",
                        "1696869003456",
                        "AIS_USER_PASSWORD_RESET_AND_IDENTITY_VERIFIED",
                        "1696969322935",
                        "1696875903456"),
                new State(blocked, suspended, reproveIdentity, resetPassword));
    }

    private Map<String, String> getHeaders() {
        Map<String, String> headers = new HashMap<>();
        headers.put("Session-Id", session.getSessionId());
        headers.put("di-persistent-session-id", TEST_PERSISTENT_SESSION_ID);
        headers.put("X-Forwarded-For", TEST_IP_ADDRESS);
        return headers;
    }

    private static ClientSession getClientSession() {
        ResponseType responseType = new ResponseType(ResponseType.Value.CODE);
        Scope scope = new Scope();
        scope.add(OIDCScopeValue.OPENID);
        AuthenticationRequest authRequest =
                new AuthenticationRequest.Builder(
                                responseType,
                                scope,
                                new ClientID(TEST_CLIENT_ID),
                                URI.create("http://localhost/redirect"))
                        .build();
        return new ClientSession(
                authRequest.toParameters(), null, mock(VectorOfTrust.class), TEST_CLIENT_NAME);
    }

    private static Stream<Arguments> httpErrorCodesAndAssociatedResponses() {
        return Stream.of(
                Arguments.of(429, ErrorResponse.ERROR_1051),
                Arguments.of(500, ErrorResponse.ERROR_1052),
                Arguments.of(502, ErrorResponse.ERROR_1053),
                Arguments.of(504, ErrorResponse.ERROR_1054),
                Arguments.of(404, ErrorResponse.ERROR_1055));
    }

    private APIGatewayProxyRequestEvent apiRequestEventWithEmail(String email) {
        var event = new APIGatewayProxyRequestEvent();
        event.setHeaders(getHeaders());
        event.setBody(format("{ \"email\": \"%s\" }", email));
        return event;
    }
}
