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
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.helpers.SaltHelper;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.*;
import uk.gov.di.authentication.shared.state.UserContext;

import java.net.URI;
import java.net.URISyntaxException;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import static java.lang.String.format;
import static java.time.Clock.fixed;
import static java.time.ZoneId.systemDefault;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.*;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.NO_INTERVENTION;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.PERMANENTLY_BLOCKED_INTERVENTION;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.CLIENT_SESSION_ID;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.EMAIL;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.ENCODED_DEVICE_DETAILS;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.IP_ADDRESS;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.PERSISTENT_ID;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.SESSION_ID;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.TEST_CLIENT_ID;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.TEST_CLIENT_NAME;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

public class AccountInterventionsHandlerTest {
    private static final String TEST_INTERNAL_SUBJECT_ID = "test-internal-subject-id";
    private static final String TEST_SUBJECT_ID = "subject-id";
    private static final String INTERNAL_SECTOR_URI = "https://test.account.gov.uk";
    private static final String TEST_ENVIRONMENT = "test-environment";
    private static final String APPLIED_AT_TIMESTAMP = "1696869005821";

    private static final Instant fixedDate = Instant.now();

    private static final String fixedDateUnixTimestampString =
            String.valueOf(fixedDate.toEpochMilli());
    private final String DEFAULT_NO_INTERVENTIONS_RESPONSE =
            String.format(
                    "{\"passwordResetRequired\":%b,\"blocked\":%b,\"temporarilySuspended\":%b,\"reproveIdentity\":%b,\"appliedAt\":\"%s\"}",
                    false, false, false, false, fixedDateUnixTimestampString);
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
                    .setEmailAddress(EMAIL)
                    .setSessionId(SESSION_ID)
                    .setInternalCommonSubjectIdentifier(TEST_INTERNAL_SUBJECT_ID);
    private static final Json objectMapper = SerializationService.getInstance();

    @BeforeEach
    void setUp() throws URISyntaxException {
        when(context.getAwsRequestId()).thenReturn("aws-session-id");
        when(sessionService.getSessionFromRequestHeaders(anyMap()))
                .thenReturn(Optional.of(session));
        UserProfile userProfile = generateUserProfile();
        when(authenticationService.getUserProfileByEmailMaybe(EMAIL))
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
        when(userContext.getClientSessionId()).thenReturn(CLIENT_SESSION_ID);
        when(userContext.getTxmaAuditEncoded()).thenReturn(ENCODED_DEVICE_DETAILS);
        when(configurationService.getAccountInterventionsErrorMetricName())
                .thenReturn("AISException");
        when(configurationService.getEnvironment()).thenReturn(TEST_ENVIRONMENT);
        var fixedClock = new NowHelper.NowClock(fixed(fixedDate, systemDefault()));
        handler =
                new AccountInterventionsHandler(
                        configurationService,
                        sessionService,
                        clientSessionService,
                        clientService,
                        authenticationService,
                        accountInterventionsService,
                        auditService,
                        cloudwatchMetricsService,
                        fixedClock);
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
        var result = handler.handleRequest(apiRequestEventWithEmail(EMAIL), context);
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
        var result = handler.handleRequest(apiRequestEventWithEmail(EMAIL), context);
        assertThat(result, hasStatus(httpCode));
        assertThat(result, hasBody(objectMapper.writeValueAsString(expectedErrorResponse)));
    }

    @Test
    void
            shouldReturn200AndDefaultAccountInterventionsResponseWhenAccountInterventionsRequestUnsuccessfulAndAbortOnErrorIsFalse()
                    throws UnsuccessfulAccountInterventionsResponseException {
        when(configurationService.abortOnAccountInterventionsErrorResponse()).thenReturn(false);
        when(authenticationService.getUserProfileByEmailMaybe(anyString()))
                .thenReturn(Optional.of(generateUserProfile()));
        when(accountInterventionsService.sendAccountInterventionsOutboundRequest(any()))
                .thenThrow(
                        new UnsuccessfulAccountInterventionsResponseException(
                                "Any 4xx/5xx error valid here", 404));
        var result = handler.handleRequest(apiRequestEventWithEmail(EMAIL), context);
        assertThat(result, hasStatus(200));
        assertEquals(DEFAULT_NO_INTERVENTIONS_RESPONSE, result.getBody());
        verify(cloudwatchMetricsService)
                .incrementCounter("AuthAISException", Map.of("Environment", "test-environment"));
        verify(cloudwatchMetricsService)
                .incrementCounter("AuthAisErrorIgnored", Map.of("Environment", "test-environment"));
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
        var result = handler.handleRequest(apiRequestEventWithEmail(EMAIL), context);
        assertThat(result, hasStatus(200));
        assertEquals(DEFAULT_NO_INTERVENTIONS_RESPONSE, result.getBody());
    }

    @Test
    void
            shouldReturn200AndDefaultAccountInterventionsResponseWhenAccountInterventionsServiceActionDisabledAndAccountHasInterventions()
                    throws UnsuccessfulAccountInterventionsResponseException {
        when(configurationService.accountInterventionsServiceActionEnabled()).thenReturn(false);
        when(authenticationService.getUserProfileByEmailMaybe(anyString()))
                .thenReturn(Optional.of(generateUserProfile()));
        when(accountInterventionsService.sendAccountInterventionsOutboundRequest(any()))
                .thenReturn(
                        generateAccountInterventionResponse(
                                true, true, true, true, APPLIED_AT_TIMESTAMP));
        var result = handler.handleRequest(apiRequestEventWithEmail(EMAIL), context);
        assertThat(result, hasStatus(200));
        assertEquals(DEFAULT_NO_INTERVENTIONS_RESPONSE, result.getBody());
    }

    @Test
    void shouldReturn200NotCallAccountInterventionsServiceWhenCallIsDiabled()
            throws UnsuccessfulAccountInterventionsResponseException {
        when(configurationService.isAccountInterventionServiceCallEnabled()).thenReturn(false);
        var result = handler.handleRequest(apiRequestEventWithEmail(EMAIL), context);

        verify(accountInterventionsService, never()).sendAccountInterventionsOutboundRequest(any());
        assertThat(result, hasStatus(200));
        assertEquals(DEFAULT_NO_INTERVENTIONS_RESPONSE, result.getBody());
    }

    static Stream<Arguments> accountInterventionResponseParameters() {
        Stream<Arguments> argumentsStream =
                Stream.of(
                        Arguments.of(false, false, false, false, NO_INTERVENTION),
                        Arguments.of(false, true, true, false, NO_INTERVENTION),
                        Arguments.of(true, false, false, false, PERMANENTLY_BLOCKED_INTERVENTION),
                        Arguments.of(false, true, false, false, TEMP_SUSPENDED_INTERVENTION),
                        Arguments.of(false, true, false, true, PASSWORD_RESET_INTERVENTION),
                        Arguments.of(false, true, true, true, PASSWORD_RESET_INTERVENTION));
        return argumentsStream;
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
        var event = apiRequestEventWithEmail(EMAIL);
        when(authenticationService.getUserProfileByEmailMaybe(anyString()))
                .thenReturn(Optional.of(generateUserProfile()));
        when(accountInterventionsService.sendAccountInterventionsOutboundRequest(any()))
                .thenReturn(
                        generateAccountInterventionResponse(
                                blocked,
                                suspended,
                                reproveIdentity,
                                resetPassword,
                                APPLIED_AT_TIMESTAMP));

        var result =
                handler.handleRequestWithUserContext(
                        event, context, new AccountInterventionsRequest("test"), userContext);
        assertThat(result, hasStatus(200));

        assertEquals(
                String.format(
                        "{\"passwordResetRequired\":%b,\"blocked\":%b,\"temporarilySuspended\":%b,\"reproveIdentity\":%b,\"appliedAt\":\"%s\"}",
                        resetPassword, blocked, suspended, reproveIdentity, APPLIED_AT_TIMESTAMP),
                result.getBody());
        var expectedMetricDimensions =
                Map.of(
                        "Environment",
                        TEST_ENVIRONMENT,
                        "blocked",
                        String.valueOf(blocked),
                        "suspended",
                        String.valueOf(suspended),
                        "reproveIdentity",
                        String.valueOf(reproveIdentity),
                        "resetPassword",
                        String.valueOf(resetPassword));
        verify(cloudwatchMetricsService)
                .incrementCounter("AuthAisResult", expectedMetricDimensions);
        verify(auditService)
                .submitAuditEvent(
                        expectedEvent,
                        TEST_CLIENT_ID,
                        CLIENT_SESSION_ID,
                        SESSION_ID,
                        TEST_INTERNAL_SUBJECT_ID,
                        EMAIL,
                        IP_ADDRESS,
                        AuditService.UNKNOWN,
                        PERSISTENT_ID,
                        new AuditService.RestrictedSection(Optional.of(ENCODED_DEVICE_DETAILS)));
    }

    @Test
    void checkAuditEventStillEmittedWhenTICFHeaderNotProvided()
            throws UnsuccessfulAccountInterventionsResponseException, Json.JsonException {
        boolean blocked = false;
        boolean suspended = false;
        boolean reproveIdentity = false;
        boolean resetPassword = false;
        FrontendAuditableEvent expectedEvent = NO_INTERVENTION;
        var event = apiRequestEventWithEmail(EMAIL);
        when(authenticationService.getUserProfileByEmailMaybe(anyString()))
                .thenReturn(Optional.of(generateUserProfile()));
        when(accountInterventionsService.sendAccountInterventionsOutboundRequest(any()))
                .thenReturn(
                        generateAccountInterventionResponse(
                                blocked,
                                suspended,
                                reproveIdentity,
                                resetPassword,
                                APPLIED_AT_TIMESTAMP));
        when(userContext.getTxmaAuditEncoded()).thenReturn(null);

        var result =
                handler.handleRequestWithUserContext(
                        event, context, new AccountInterventionsRequest("test"), userContext);

        assertThat(result, hasStatus(200));

        verify(auditService)
                .submitAuditEvent(
                        expectedEvent,
                        TEST_CLIENT_ID,
                        CLIENT_SESSION_ID,
                        SESSION_ID,
                        TEST_INTERNAL_SUBJECT_ID,
                        EMAIL,
                        IP_ADDRESS,
                        AuditService.UNKNOWN,
                        PERSISTENT_ID,
                        AuditService.RestrictedSection.empty);
    }

    private UserProfile generateUserProfile() {
        return new UserProfile()
                .withEmail(EMAIL)
                .withEmailVerified(true)
                .withPhoneNumberVerified(true)
                .withPublicSubjectID(new Subject().getValue())
                .withSubjectID(TEST_SUBJECT_ID);
    }

    private AccountInterventionsInboundResponse generateAccountInterventionResponse(
            boolean blocked,
            boolean suspended,
            boolean reproveIdentity,
            boolean resetPassword,
            String appliedAtTimestamp) {
        return new AccountInterventionsInboundResponse(
                new Intervention(
                        "1696969322935",
                        appliedAtTimestamp,
                        "1696869003456",
                        "AIS_USER_PASSWORD_RESET_AND_IDENTITY_VERIFIED",
                        "1696969322935",
                        "1696875903456"),
                new State(blocked, suspended, reproveIdentity, resetPassword));
    }

    private Map<String, String> getHeaders() {
        Map<String, String> headers = new HashMap<>();
        headers.put("Session-Id", session.getSessionId());
        headers.put("di-persistent-session-id", PERSISTENT_ID);
        headers.put("X-Forwarded-For", IP_ADDRESS);
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
