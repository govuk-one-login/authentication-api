package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.google.gson.Gson;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.entity.InternalTICFCRIRequest;
import uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent;
import uk.gov.di.authentication.frontendapi.entity.AccountInterventionsRequest;
import uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables;
import uk.gov.di.authentication.shared.entity.AccountInterventionsInboundResponse;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.entity.AuthSessionItem.AccountState;
import uk.gov.di.authentication.shared.entity.AuthSessionItem.ResetMfaState;
import uk.gov.di.authentication.shared.entity.AuthSessionItem.ResetPasswordState;
import uk.gov.di.authentication.shared.entity.ClientSession;
import uk.gov.di.authentication.shared.entity.CredentialTrustLevel;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.Intervention;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.State;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.entity.VectorOfTrust;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.exceptions.UnsuccessfulAccountInterventionsResponseException;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.AccountInterventionsService;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthSessionService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.LambdaInvokerService;
import uk.gov.di.authentication.shared.services.SerializationService;
import uk.gov.di.authentication.shared.services.SessionService;
import uk.gov.di.authentication.shared.state.UserContext;
import uk.gov.di.authentication.sharedtest.logging.CaptureLoggingExtension;

import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
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
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_NO_INTERVENTION;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_PASSWORD_RESET_INTERVENTION;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_PERMANENTLY_BLOCKED_INTERVENTION;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_TEMP_SUSPENDED_INTERVENTION;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.CLIENT_NAME;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.EMAIL;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.SESSION_ID;
import static uk.gov.di.authentication.frontendapi.lambda.LoginHandler.INTERNAL_SUBJECT_ID;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class AccountInterventionsHandlerTest {
    private static final String TEST_CLIENT_ID = "test_client_id";
    private static final String TEST_SUBJECT_ID = "subject-id";
    private static final String INTERNAL_SECTOR_URI = "https://test.account.gov.uk";
    private static final byte[] SALT = "a-test-salt".getBytes(StandardCharsets.UTF_8);
    private static final String TEST_ENVIRONMENT = "test-environment";
    private static final Long APPLIED_AT_TIMESTAMP = 1696869005821L;

    private static final Instant fixedDate = Instant.now();

    private static final String FIXED_DATE_UNIX_TIMESTAMP_STRING =
            String.valueOf(fixedDate.toEpochMilli());
    private static final String DEFAULT_NO_INTERVENTIONS_RESPONSE =
            String.format(
                    "{\"passwordResetRequired\":%b,\"blocked\":%b,\"temporarilySuspended\":%b,\"reproveIdentity\":%b,\"appliedAt\":%s}",
                    false, false, false, false, FIXED_DATE_UNIX_TIMESTAMP_STRING);
    private AccountInterventionsHandler handler;
    private final Context context = mock(Context.class);

    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final SessionService sessionService = mock(SessionService.class);
    private final ClientSessionService clientSessionService = mock(ClientSessionService.class);
    private final AuthenticationService authenticationService = mock(AuthenticationService.class);
    private final AuditService auditService = mock(AuditService.class);
    private final UserContext userContext = mock(UserContext.class, Mockito.RETURNS_DEEP_STUBS);
    private final AccountInterventionsService accountInterventionsService =
            mock(AccountInterventionsService.class);
    private final ClientService clientService = mock(ClientService.class);
    private final CloudwatchMetricsService cloudwatchMetricsService =
            mock(CloudwatchMetricsService.class);
    private final LambdaInvokerService mockLambdaInvokerService = mock(LambdaInvokerService.class);
    private final AuthSessionService authSessionService = mock(AuthSessionService.class);

    private static final ClientSession clientSession = getClientSession();
    private final Session session = new Session();
    private final AuthSessionItem authSession =
            new AuthSessionItem()
                    .withSessionId(SESSION_ID)
                    .withEmailAddress(EMAIL)
                    .withInternalCommonSubjectId(INTERNAL_SUBJECT_ID)
                    .withRequestedCredentialStrength(CredentialTrustLevel.LOW_LEVEL);

    private static final AuditContext AUDIT_CONTEXT =
            new AuditContext(
                    CommonTestVariables.CLIENT_ID,
                    CommonTestVariables.CLIENT_SESSION_ID,
                    CommonTestVariables.SESSION_ID,
                    INTERNAL_SUBJECT_ID,
                    EMAIL,
                    CommonTestVariables.IP_ADDRESS,
                    AuditService.UNKNOWN,
                    CommonTestVariables.DI_PERSISTENT_SESSION_ID,
                    Optional.of(CommonTestVariables.ENCODED_DEVICE_DETAILS));
    private static final Json objectMapper = SerializationService.getInstance();

    @RegisterExtension
    public final CaptureLoggingExtension logging =
            new CaptureLoggingExtension(AccountInterventionsHandler.class);

    @BeforeEach
    void setUp() throws URISyntaxException {
        when(context.getAwsRequestId()).thenReturn("aws-session-id");
        when(sessionService.getSessionFromRequestHeaders(anyMap()))
                .thenReturn(Optional.of(session));
        when(authSessionService.getSessionFromRequestHeaders(anyMap()))
                .thenReturn(Optional.of(authSession));
        UserProfile userProfile = generateUserProfile();
        when(authenticationService.getUserProfileByEmailMaybe(EMAIL))
                .thenReturn(Optional.of(userProfile));
        when(configurationService.accountInterventionsServiceActionEnabled()).thenReturn(true);
        when(configurationService.isAccountInterventionServiceCallEnabled()).thenReturn(true);
        when(configurationService.getInternalSectorUri()).thenReturn(INTERNAL_SECTOR_URI);
        when(authenticationService.getOrGenerateSalt(any(UserProfile.class))).thenReturn(SALT);
        when(configurationService.getAccountInterventionServiceURI())
                .thenReturn(new URI("https://account-interventions.gov.uk/v1"));
        when(configurationService.getAwsRegion()).thenReturn("eu-west-2");
        when(userContext.getSession()).thenReturn(session);
        when(userContext.getAuthSession()).thenReturn(authSession);
        when(userContext.getClientSession()).thenReturn(clientSession);
        when(userContext.getClientId()).thenReturn(CommonTestVariables.CLIENT_ID);
        when(userContext.getClientSessionId()).thenReturn(CommonTestVariables.CLIENT_SESSION_ID);
        when(userContext.getTxmaAuditEncoded())
                .thenReturn(CommonTestVariables.ENCODED_DEVICE_DETAILS);
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
                        cloudwatchMetricsService,
                        new NowHelper.NowClock(fixed(fixedDate, systemDefault())),
                        mockLambdaInvokerService,
                        authSessionService);
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

        var result = handler.handleRequest(apiRequestEventWithEmail(), context);

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
        var result = handler.handleRequest(apiRequestEventWithEmail(), context);
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
                .thenReturn(generateAccountInterventionResponse(true, true, true, true));

        var result =
                handler.handleRequestWithUserContext(
                        apiRequestEventWithEmail(),
                        context,
                        new AccountInterventionsRequest("test", true),
                        userContext);

        assertThat(result, hasStatus(200));
        assertEquals(DEFAULT_NO_INTERVENTIONS_RESPONSE, result.getBody());
    }

    @ParameterizedTest
    @CsvSource({"true", "false"})
    void checkInvokesTICFLambdaWhenFeatureSwitchOn(boolean featureSwitch)
            throws UnsuccessfulAccountInterventionsResponseException {
        when(configurationService.accountInterventionsServiceActionEnabled()).thenReturn(false);
        when(authenticationService.getUserProfileByEmailMaybe(anyString()))
                .thenReturn(Optional.of(generateUserProfile()));
        when(accountInterventionsService.sendAccountInterventionsOutboundRequest(any()))
                .thenReturn(generateAccountInterventionResponse(true, true, true, true));

        when(configurationService.isInvokeTicfCRILambdaEnabled()).thenReturn(featureSwitch);

        var result =
                handler.handleRequestWithUserContext(
                        apiRequestEventWithEmail(),
                        context,
                        new AccountInterventionsRequest("test", true),
                        userContext);

        assertThat(result, hasStatus(200));
        assertEquals(DEFAULT_NO_INTERVENTIONS_RESPONSE, result.getBody());
        if (featureSwitch) {
            verify(mockLambdaInvokerService, times(1)).invokeAsyncWithPayload(any(), any());
        } else {
            verify(mockLambdaInvokerService, times(0)).invokeAsyncWithPayload(any(), any());
        }
    }

    private static Stream<Arguments> ticfParametersSource() {
        return Stream.of(
                // Testing authenticated combinations
                Arguments.of(
                        true,
                        AccountState.EXISTING,
                        ResetPasswordState.NONE,
                        ResetMfaState.NONE,
                        MFAMethodType.NONE,
                        "{\"internalCommonSubjectIdentifier\":\"urn:fdc:gov.uk:2022:mSm2hCZ-klPlOON7Z_KbaheBxJu88nDWbUn7fR6xD2g\",\"vtr\":[\"Cl\"],\"govukSigninJourneyId\":\"known-client-session-id\",\"authenticated\":true,\"accountState\":\"EXISTING\",\"resetPasswordState\":\"NONE\",\"resetMfaState\":\"NONE\",\"mfaMethodType\":\"NONE\"}"),
                Arguments.of(
                        false,
                        AccountState.EXISTING,
                        ResetPasswordState.NONE,
                        ResetMfaState.NONE,
                        MFAMethodType.NONE,
                        "{\"internalCommonSubjectIdentifier\":\"urn:fdc:gov.uk:2022:mSm2hCZ-klPlOON7Z_KbaheBxJu88nDWbUn7fR6xD2g\",\"vtr\":[\"Cl\"],\"govukSigninJourneyId\":\"known-client-session-id\",\"authenticated\":false,\"accountState\":\"EXISTING\",\"resetPasswordState\":\"NONE\",\"resetMfaState\":\"NONE\",\"mfaMethodType\":\"NONE\"}"),

                // Testing initial registration combinations
                Arguments.of(
                        true,
                        AccountState.NEW,
                        ResetPasswordState.NONE,
                        ResetMfaState.NONE,
                        MFAMethodType.NONE,
                        "{\"internalCommonSubjectIdentifier\":\"urn:fdc:gov.uk:2022:mSm2hCZ-klPlOON7Z_KbaheBxJu88nDWbUn7fR6xD2g\",\"vtr\":[\"Cl\"],\"govukSigninJourneyId\":\"known-client-session-id\",\"authenticated\":true,\"accountState\":\"NEW\",\"resetPasswordState\":\"NONE\",\"resetMfaState\":\"NONE\",\"mfaMethodType\":\"NONE\"}"),
                Arguments.of(
                        false,
                        AccountState.NEW,
                        ResetPasswordState.NONE,
                        ResetMfaState.NONE,
                        MFAMethodType.NONE,
                        "{\"internalCommonSubjectIdentifier\":\"urn:fdc:gov.uk:2022:mSm2hCZ-klPlOON7Z_KbaheBxJu88nDWbUn7fR6xD2g\",\"vtr\":[\"Cl\"],\"govukSigninJourneyId\":\"known-client-session-id\",\"authenticated\":false,\"accountState\":\"NEW\",\"resetPasswordState\":\"NONE\",\"resetMfaState\":\"NONE\",\"mfaMethodType\":\"NONE\"}"),

                // Testing password reset combinations
                Arguments.of(
                        true,
                        AccountState.EXISTING,
                        ResetPasswordState.SUCCEEDED,
                        ResetMfaState.NONE,
                        MFAMethodType.NONE,
                        "{\"internalCommonSubjectIdentifier\":\"urn:fdc:gov.uk:2022:mSm2hCZ-klPlOON7Z_KbaheBxJu88nDWbUn7fR6xD2g\",\"vtr\":[\"Cl\"],\"govukSigninJourneyId\":\"known-client-session-id\",\"authenticated\":true,\"accountState\":\"EXISTING\",\"resetPasswordState\":\"SUCCEEDED\",\"resetMfaState\":\"NONE\",\"mfaMethodType\":\"NONE\"}"),
                Arguments.of(
                        false,
                        AccountState.EXISTING,
                        ResetPasswordState.ATTEMPTED,
                        ResetMfaState.NONE,
                        MFAMethodType.NONE,
                        "{\"internalCommonSubjectIdentifier\":\"urn:fdc:gov.uk:2022:mSm2hCZ-klPlOON7Z_KbaheBxJu88nDWbUn7fR6xD2g\",\"vtr\":[\"Cl\"],\"govukSigninJourneyId\":\"known-client-session-id\",\"authenticated\":false,\"accountState\":\"EXISTING\",\"resetPasswordState\":\"ATTEMPTED\",\"resetMfaState\":\"NONE\",\"mfaMethodType\":\"NONE\"}"),

                // Testing mfa reset combinations
                Arguments.of(
                        true,
                        AccountState.EXISTING,
                        ResetPasswordState.NONE,
                        ResetMfaState.SUCCEEDED,
                        MFAMethodType.NONE,
                        "{\"internalCommonSubjectIdentifier\":\"urn:fdc:gov.uk:2022:mSm2hCZ-klPlOON7Z_KbaheBxJu88nDWbUn7fR6xD2g\",\"vtr\":[\"Cl\"],\"govukSigninJourneyId\":\"known-client-session-id\",\"authenticated\":true,\"accountState\":\"EXISTING\",\"resetPasswordState\":\"NONE\",\"resetMfaState\":\"SUCCEEDED\",\"mfaMethodType\":\"NONE\"}"),
                Arguments.of(
                        true,
                        AccountState.EXISTING,
                        ResetPasswordState.NONE,
                        ResetMfaState.ATTEMPTED,
                        MFAMethodType.NONE,
                        "{\"internalCommonSubjectIdentifier\":\"urn:fdc:gov.uk:2022:mSm2hCZ-klPlOON7Z_KbaheBxJu88nDWbUn7fR6xD2g\",\"vtr\":[\"Cl\"],\"govukSigninJourneyId\":\"known-client-session-id\",\"authenticated\":true,\"accountState\":\"EXISTING\",\"resetPasswordState\":\"NONE\",\"resetMfaState\":\"ATTEMPTED\",\"mfaMethodType\":\"NONE\"}"),
                Arguments.of(
                        false,
                        AccountState.EXISTING,
                        ResetPasswordState.NONE,
                        ResetMfaState.ATTEMPTED,
                        MFAMethodType.NONE,
                        "{\"internalCommonSubjectIdentifier\":\"urn:fdc:gov.uk:2022:mSm2hCZ-klPlOON7Z_KbaheBxJu88nDWbUn7fR6xD2g\",\"vtr\":[\"Cl\"],\"govukSigninJourneyId\":\"known-client-session-id\",\"authenticated\":false,\"accountState\":\"EXISTING\",\"resetPasswordState\":\"NONE\",\"resetMfaState\":\"ATTEMPTED\",\"mfaMethodType\":\"NONE\"}"),

                // Testing mfa method combinations
                Arguments.of(
                        true,
                        AccountState.EXISTING,
                        ResetPasswordState.NONE,
                        ResetMfaState.NONE,
                        MFAMethodType.NONE,
                        "{\"internalCommonSubjectIdentifier\":\"urn:fdc:gov.uk:2022:mSm2hCZ-klPlOON7Z_KbaheBxJu88nDWbUn7fR6xD2g\",\"vtr\":[\"Cl\"],\"govukSigninJourneyId\":\"known-client-session-id\",\"authenticated\":true,\"accountState\":\"EXISTING\",\"resetPasswordState\":\"NONE\",\"resetMfaState\":\"NONE\",\"mfaMethodType\":\"NONE\"}"),
                Arguments.of(
                        true,
                        AccountState.EXISTING,
                        ResetPasswordState.NONE,
                        ResetMfaState.NONE,
                        MFAMethodType.EMAIL,
                        "{\"internalCommonSubjectIdentifier\":\"urn:fdc:gov.uk:2022:mSm2hCZ-klPlOON7Z_KbaheBxJu88nDWbUn7fR6xD2g\",\"vtr\":[\"Cl\"],\"govukSigninJourneyId\":\"known-client-session-id\",\"authenticated\":true,\"accountState\":\"EXISTING\",\"resetPasswordState\":\"NONE\",\"resetMfaState\":\"NONE\",\"mfaMethodType\":\"EMAIL\"}"),
                Arguments.of(
                        true,
                        AccountState.EXISTING,
                        ResetPasswordState.NONE,
                        ResetMfaState.NONE,
                        MFAMethodType.SMS,
                        "{\"internalCommonSubjectIdentifier\":\"urn:fdc:gov.uk:2022:mSm2hCZ-klPlOON7Z_KbaheBxJu88nDWbUn7fR6xD2g\",\"vtr\":[\"Cl\"],\"govukSigninJourneyId\":\"known-client-session-id\",\"authenticated\":true,\"accountState\":\"EXISTING\",\"resetPasswordState\":\"NONE\",\"resetMfaState\":\"NONE\",\"mfaMethodType\":\"SMS\"}"),
                Arguments.of(
                        true,
                        AccountState.EXISTING,
                        ResetPasswordState.NONE,
                        ResetMfaState.NONE,
                        MFAMethodType.AUTH_APP,
                        "{\"internalCommonSubjectIdentifier\":\"urn:fdc:gov.uk:2022:mSm2hCZ-klPlOON7Z_KbaheBxJu88nDWbUn7fR6xD2g\",\"vtr\":[\"Cl\"],\"govukSigninJourneyId\":\"known-client-session-id\",\"authenticated\":true,\"accountState\":\"EXISTING\",\"resetPasswordState\":\"NONE\",\"resetMfaState\":\"NONE\",\"mfaMethodType\":\"AUTH_APP\"}"));
    }

    @ParameterizedTest
    @MethodSource("ticfParametersSource")
    void checkInvokesTICFLambdaWithCorrectValues(
            boolean authenticated,
            AccountState accountState,
            ResetPasswordState resetPasswordState,
            ResetMfaState resetMfaState,
            MFAMethodType usedMfaMethodType,
            String expectedPayload)
            throws UnsuccessfulAccountInterventionsResponseException {
        when(configurationService.accountInterventionsServiceActionEnabled()).thenReturn(false);
        when(authenticationService.getUserProfileByEmailMaybe(anyString()))
                .thenReturn(Optional.of(generateUserProfile()));
        when(accountInterventionsService.sendAccountInterventionsOutboundRequest(any()))
                .thenReturn(generateAccountInterventionResponse(true, true, true, true));
        when(configurationService.isInvokeTicfCRILambdaEnabled()).thenReturn(true);
        var authSessionWithChanges =
                authSession
                        .withAccountState(accountState)
                        .withResetPasswordState(resetPasswordState)
                        .withResetMfaState(resetMfaState)
                        .withVerifiedMfaMethodType(usedMfaMethodType);
        when(authSessionService.getSessionFromRequestHeaders(anyMap()))
                .thenReturn(Optional.of(authSessionWithChanges));

        var result =
                handler.handleRequestWithUserContext(
                        apiRequestEventForTICF(authenticated),
                        context,
                        new AccountInterventionsRequest("test", authenticated),
                        userContext);

        assertThat(result, hasStatus(200));
        assertEquals(DEFAULT_NO_INTERVENTIONS_RESPONSE, result.getBody());
        verify(mockLambdaInvokerService, times(1))
                .invokeAsyncWithPayload(eq(expectedPayload), any());
    }

    private static Stream<Boolean> authenticatedUserSource() {
        return Stream.of(Boolean.TRUE, Boolean.FALSE, null);
    }

    @ParameterizedTest
    @MethodSource("authenticatedUserSource")
    void checkDoesNotInvokesTICFLambdaForUsersWithUnknownAuthenticationStatus(Boolean authenticated)
            throws UnsuccessfulAccountInterventionsResponseException {
        when(configurationService.accountInterventionsServiceActionEnabled()).thenReturn(false);
        when(authenticationService.getUserProfileByEmailMaybe(anyString()))
                .thenReturn(Optional.of(generateUserProfile()));
        when(accountInterventionsService.sendAccountInterventionsOutboundRequest(any()))
                .thenReturn(generateAccountInterventionResponse(true, true, true, true));

        when(configurationService.isInvokeTicfCRILambdaEnabled()).thenReturn(true);

        var result =
                handler.handleRequestWithUserContext(
                        apiRequestEventWithEmail(),
                        context,
                        new AccountInterventionsRequest("test", authenticated),
                        userContext);

        assertThat(result, hasStatus(200));
        assertEquals(DEFAULT_NO_INTERVENTIONS_RESPONSE, result.getBody());
        if (authenticated != null) {
            verify(mockLambdaInvokerService, times(1)).invokeAsyncWithPayload(any(), any());
        } else {
            verify(mockLambdaInvokerService, times(0)).invokeAsyncWithPayload(any(), any());
        }
    }

    @Test
    void checkMissingVTRDoesNotImpactUserJourney()
            throws UnsuccessfulAccountInterventionsResponseException {
        when(configurationService.accountInterventionsServiceActionEnabled()).thenReturn(false);
        when(authenticationService.getUserProfileByEmailMaybe(anyString()))
                .thenReturn(Optional.of(generateUserProfile()));
        when(accountInterventionsService.sendAccountInterventionsOutboundRequest(any()))
                .thenReturn(generateAccountInterventionResponse(true, true, true, true));

        when(configurationService.isInvokeTicfCRILambdaEnabled()).thenReturn(true);
        when(userContext.getClientSession()).thenReturn(null);

        var result =
                handler.handleRequestWithUserContext(
                        apiRequestEventWithEmail(),
                        context,
                        new AccountInterventionsRequest("test", true),
                        userContext);

        assertThat(result, hasStatus(200));
        assertEquals(DEFAULT_NO_INTERVENTIONS_RESPONSE, result.getBody());
        verify(mockLambdaInvokerService, times(1)).invokeAsyncWithPayload(any(), any());
    }

    @Test
    void shouldReturn200NotCallAccountInterventionsServiceWhenCallIsDisabled()
            throws UnsuccessfulAccountInterventionsResponseException {
        when(configurationService.isAccountInterventionServiceCallEnabled()).thenReturn(false);

        var result = handler.handleRequest(apiRequestEventWithEmail(), context);

        verify(accountInterventionsService, never()).sendAccountInterventionsOutboundRequest(any());
        assertThat(result, hasStatus(200));
        assertEquals(DEFAULT_NO_INTERVENTIONS_RESPONSE, result.getBody());
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

        var result = handler.handleRequest(apiRequestEventWithEmail(), context);

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

        var result = handler.handleRequest(apiRequestEventWithEmail(), context);

        assertThat(result, hasStatus(httpCode));
        assertThat(result, hasBody(objectMapper.writeValueAsString(expectedErrorResponse)));
    }

    static Stream<Arguments> accountInterventionResponseParameters() {
        return Stream.of(
                Arguments.of(false, false, false, false, AUTH_NO_INTERVENTION),
                Arguments.of(false, true, true, false, AUTH_NO_INTERVENTION),
                Arguments.of(true, false, false, false, AUTH_PERMANENTLY_BLOCKED_INTERVENTION),
                Arguments.of(false, true, false, false, AUTH_TEMP_SUSPENDED_INTERVENTION),
                Arguments.of(false, true, false, true, AUTH_PASSWORD_RESET_INTERVENTION),
                Arguments.of(false, true, true, true, AUTH_PASSWORD_RESET_INTERVENTION));
    }

    @ParameterizedTest
    @MethodSource("accountInterventionResponseParameters")
    void shouldReturn200ForSuccessfulRequestAndSubmitAppropriateAuditEvents(
            boolean blocked,
            boolean suspended,
            boolean reproveIdentity,
            boolean resetPassword,
            FrontendAuditableEvent expectedEvent)
            throws UnsuccessfulAccountInterventionsResponseException {
        var event = apiRequestEventWithEmail();
        when(authenticationService.getUserProfileByEmailMaybe(anyString()))
                .thenReturn(Optional.of(generateUserProfile()));
        when(accountInterventionsService.sendAccountInterventionsOutboundRequest(any()))
                .thenReturn(
                        generateAccountInterventionResponse(
                                blocked, suspended, reproveIdentity, resetPassword));

        when(configurationService.isInvokeTicfCRILambdaEnabled()).thenReturn(true);

        var result =
                handler.handleRequestWithUserContext(
                        event, context, new AccountInterventionsRequest("test", true), userContext);

        assertThat(result, hasStatus(200));

        assertEquals(
                String.format(
                        "{\"passwordResetRequired\":%b,\"blocked\":%b,\"temporarilySuspended\":%b,\"reproveIdentity\":%b,\"appliedAt\":%s}",
                        resetPassword, blocked, suspended, reproveIdentity, APPLIED_AT_TIMESTAMP),
                result.getBody());
        var expectedMetricDimensions =
                Map.ofEntries(
                        Map.entry("Environment", TEST_ENVIRONMENT),
                        Map.entry("blocked", String.valueOf(blocked)),
                        Map.entry("suspended", String.valueOf(suspended)),
                        Map.entry("reproveIdentity", String.valueOf(reproveIdentity)),
                        Map.entry("resetPassword", String.valueOf(resetPassword)));
        verify(cloudwatchMetricsService)
                .incrementCounter("AuthAisResult", expectedMetricDimensions);
        ArgumentCaptor<String> payloadCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> lambdaNameCaptor = ArgumentCaptor.forClass(String.class);

        verify(mockLambdaInvokerService)
                .invokeAsyncWithPayload(payloadCaptor.capture(), lambdaNameCaptor.capture());

        String capturedPayload = payloadCaptor.getValue();
        var ticfRequest = new Gson().fromJson(capturedPayload, InternalTICFCRIRequest.class);
        assertEquals(CommonTestVariables.CLIENT_SESSION_ID, ticfRequest.govukSigninJourneyId());
        var vtr = new ArrayList<String>();
        vtr.add(CredentialTrustLevel.LOW_LEVEL.getValue());
        assertEquals(ticfRequest.vtr(), vtr);
        verify(auditService).submitAuditEvent(expectedEvent, AUDIT_CONTEXT);
    }

    @Test
    void checkAuditEventStillEmittedWhenTICFHeaderNotProvided()
            throws UnsuccessfulAccountInterventionsResponseException {
        boolean blocked = false;
        boolean suspended = false;
        boolean reproveIdentity = false;
        boolean resetPassword = false;
        var event = apiRequestEventWithEmail();
        when(authenticationService.getUserProfileByEmailMaybe(anyString()))
                .thenReturn(Optional.of(generateUserProfile()));
        when(accountInterventionsService.sendAccountInterventionsOutboundRequest(any()))
                .thenReturn(
                        generateAccountInterventionResponse(
                                blocked, suspended, reproveIdentity, resetPassword));
        when(userContext.getTxmaAuditEncoded()).thenReturn(null);

        var result =
                handler.handleRequestWithUserContext(
                        event, context, new AccountInterventionsRequest("test", true), userContext);

        assertThat(result, hasStatus(200));

        verify(auditService)
                .submitAuditEvent(
                        AUTH_NO_INTERVENTION, AUDIT_CONTEXT.withTxmaAuditEncoded(Optional.empty()));
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
            boolean blocked, boolean suspended, boolean reproveIdentity, boolean resetPassword) {
        return new AccountInterventionsInboundResponse(
                new Intervention(AccountInterventionsHandlerTest.APPLIED_AT_TIMESTAMP),
                new State(blocked, suspended, reproveIdentity, resetPassword));
    }

    private Map<String, String> getHeaders() {
        Map<String, String> headers = new HashMap<>();
        headers.put("Session-Id", CommonTestVariables.SESSION_ID);
        headers.put("di-persistent-session-id", CommonTestVariables.DI_PERSISTENT_SESSION_ID);
        headers.put("X-Forwarded-For", CommonTestVariables.IP_ADDRESS);
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
                authRequest.toParameters(), null, mock(VectorOfTrust.class), CLIENT_NAME);
    }

    private static Stream<Arguments> httpErrorCodesAndAssociatedResponses() {
        return Stream.of(
                Arguments.of(429, ErrorResponse.ERROR_1051),
                Arguments.of(500, ErrorResponse.ERROR_1052),
                Arguments.of(502, ErrorResponse.ERROR_1053),
                Arguments.of(504, ErrorResponse.ERROR_1054),
                Arguments.of(404, ErrorResponse.ERROR_1055));
    }

    private APIGatewayProxyRequestEvent apiRequestEventWithEmail() {
        var event = new APIGatewayProxyRequestEvent();
        event.setHeaders(getHeaders());
        event.setBody(
                format(
                        "{ \"email\": \"%s\" }",
                        uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.EMAIL));
        return event;
    }

    private APIGatewayProxyRequestEvent apiRequestEventForTICF(Boolean authenticated) {
        var event = new APIGatewayProxyRequestEvent();
        event.setHeaders(getHeaders());
        event.setBody(
                format(
                        """
                                {
                                  "email": "%s",
                                  "authenticated": %s
                                }
                                """,
                        CommonTestVariables.EMAIL, authenticated));
        return event;
    }
}
