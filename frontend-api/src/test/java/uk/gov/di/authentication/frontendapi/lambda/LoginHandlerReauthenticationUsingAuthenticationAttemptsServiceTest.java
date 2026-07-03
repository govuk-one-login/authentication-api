package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent;
import uk.gov.di.authentication.frontendapi.entity.ReauthFailureReasons;
import uk.gov.di.authentication.frontendapi.services.UserMigrationService;
import uk.gov.di.authentication.shared.domain.CloudwatchMetrics;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.entity.CountType;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.entity.TermsAndConditions;
import uk.gov.di.authentication.shared.entity.UserCredentials;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethod;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.helpers.SaltHelper;
import uk.gov.di.authentication.shared.helpers.TestUserHelper;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthSessionService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;
import uk.gov.di.authentication.shared.services.CommonPasswordsService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.mfa.MFAMethodsService;
import uk.gov.di.authentication.sharedtest.helper.CommonTestVariables;
import uk.gov.di.authentication.sharedtest.logging.CaptureLoggingExtension;
import uk.gov.di.authentication.userpermissions.PermissionDecisionManager;
import uk.gov.di.authentication.userpermissions.UserActionsManager;
import uk.gov.di.authentication.userpermissions.entity.Decision;
import uk.gov.di.authentication.userpermissions.entity.ForbiddenReason;

import java.time.Instant;
import java.util.Map;
import java.util.Optional;

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.not;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.shared.domain.CloudwatchMetricDimensions.ENVIRONMENT;
import static uk.gov.di.authentication.shared.domain.CloudwatchMetricDimensions.FAILURE_REASON;
import static uk.gov.di.authentication.shared.entity.CountType.ENTER_EMAIL;
import static uk.gov.di.authentication.shared.entity.CountType.ENTER_MFA_CODE;
import static uk.gov.di.authentication.shared.entity.CountType.ENTER_PASSWORD;
import static uk.gov.di.authentication.shared.entity.JourneyType.REAUTHENTICATION;
import static uk.gov.di.authentication.shared.entity.mfa.MFAMethodType.SMS;
import static uk.gov.di.authentication.shared.services.AuditService.MetadataPair.pair;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.CLIENT_SESSION_ID;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.DI_PERSISTENT_SESSION_ID;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.ENCODED_DEVICE_DETAILS;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.IP_ADDRESS;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.SESSION_ID;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.VALID_HEADERS;
import static uk.gov.di.authentication.sharedtest.helper.RequestEventHelper.contextWithSourceIp;
import static uk.gov.di.authentication.sharedtest.logging.LogEventMatcher.withMessageContaining;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;
import static uk.gov.di.authentication.userpermissions.entity.ForbiddenReason.EXCEEDED_INCORRECT_PASSWORD_SUBMISSION_LIMIT;

class LoginHandlerReauthenticationUsingAuthenticationAttemptsServiceTest {

    private static final String EMAIL = CommonTestVariables.EMAIL;
    private static final String INTERNAL_SECTOR_URI = "https://test.account.gov.uk";
    private static final String SECTOR_IDENTIFIER_HOST = "test.com";
    public static final int MAX_ALLOWED_RETRIES = 6;
    private final UserCredentials userCredentials =
            new UserCredentials().withEmail(EMAIL).withPassword(CommonTestVariables.PASSWORD);

    private final UserCredentials userCredentialsAuthApp =
            new UserCredentials()
                    .withEmail(EMAIL)
                    .withPassword(CommonTestVariables.PASSWORD)
                    .setMfaMethod(AUTH_APP_MFA_METHOD);
    private static final ClientID CLIENT_ID = new ClientID();
    private static final String CLIENT_NAME = "client-name";
    private static final String TEST_RP_PAIRWISE_ID = "test-rp-pairwise-id";
    private static final Subject INTERNAL_SUBJECT_ID = new Subject();
    private static final byte[] SALT = SaltHelper.generateNewSalt();
    private static final MFAMethod AUTH_APP_MFA_METHOD =
            new MFAMethod()
                    .withMfaMethodType(MFAMethodType.AUTH_APP.getValue())
                    .withMethodVerified(true)
                    .withEnabled(true);
    private final Context context = mock(Context.class);
    private final Subject subject = mock(Subject.class);
    private final String expectedCommonSubject =
            ClientSubjectHelper.calculatePairwiseIdentifier(
                    INTERNAL_SUBJECT_ID.getValue(), "test.account.gov.uk", SALT);

    private final String validBodyWithReauthJourney =
            format(
                    "{ \"password\": \"%s\", \"email\": \"%s\", \"journeyType\": \"%s\"}",
                    CommonTestVariables.PASSWORD, EMAIL.toUpperCase(), REAUTHENTICATION);

    private final AuditContext auditContextWithAllUserInfo =
            new AuditContext(
                    CLIENT_ID.getValue(),
                    CLIENT_SESSION_ID,
                    SESSION_ID,
                    expectedCommonSubject,
                    EMAIL,
                    IP_ADDRESS,
                    CommonTestVariables.UK_MOBILE_NUMBER,
                    DI_PERSISTENT_SESSION_ID,
                    AuditService.UNKNOWN);

    private LoginHandler handler;

    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final AuthenticationService authenticationService = mock(AuthenticationService.class);
    private final UserMigrationService userMigrationService = mock(UserMigrationService.class);
    private final AuditService auditService = mock(AuditService.class);
    private final CloudwatchMetricsService cloudwatchMetricsService =
            mock(CloudwatchMetricsService.class);
    private final CommonPasswordsService commonPasswordsService =
            mock(CommonPasswordsService.class);
    private final AuthSessionService authSessionService = mock(AuthSessionService.class);
    private final MFAMethodsService mfaMethodsService = mock(MFAMethodsService.class);
    private final PermissionDecisionManager permissionDecisionManager =
            mock(PermissionDecisionManager.class);
    private final UserActionsManager userActionsManager = mock(UserActionsManager.class);
    private final TestUserHelper testUserHelper = mock(TestUserHelper.class);

    @RegisterExtension
    private final CaptureLoggingExtension logging = new CaptureLoggingExtension(LoginHandler.class);

    @AfterEach
    void tearDown() {
        assertThat(logging.events(), not(hasItem(withMessageContaining(SESSION_ID))));
    }

    @BeforeEach
    void setUp() {
        when(configurationService.getEnvironment()).thenReturn("test");
        when(configurationService.getMaxPasswordRetries()).thenReturn(MAX_ALLOWED_RETRIES);
        when(configurationService.getTermsAndConditionsVersion()).thenReturn("1.0");
        when(configurationService.getInternalSectorUri()).thenReturn(INTERNAL_SECTOR_URI);
        when(configurationService.getMaxEmailReAuthRetries()).thenReturn(MAX_ALLOWED_RETRIES);
        when(configurationService.getCodeMaxRetries()).thenReturn(MAX_ALLOWED_RETRIES);

        when(context.getAwsRequestId()).thenReturn("aws-session-id");

        when(authenticationService.getOrGenerateSalt(any(UserProfile.class))).thenReturn(SALT);
        when(permissionDecisionManager.canReceivePassword(any(), any()))
                .thenReturn(Result.success(new Decision.Permitted(0)));

        handler =
                new LoginHandler(
                        configurationService,
                        authenticationService,
                        userMigrationService,
                        auditService,
                        cloudwatchMetricsService,
                        commonPasswordsService,
                        authSessionService,
                        mfaMethodsService,
                        permissionDecisionManager,
                        userActionsManager,
                        testUserHelper);
    }

    @Test
    void shouldReturn400AndReportReauthFailureWhenUserAlreadyLockedOut() {
        try (MockedStatic<ClientSubjectHelper> clientSubjectHelperMockedStatic =
                Mockito.mockStatic(ClientSubjectHelper.class, Mockito.CALLS_REAL_METHODS)) {
            UserProfile userProfile = generateUserProfile(null);
            when(authenticationService.getUserProfileByEmailMaybe(EMAIL))
                    .thenReturn(Optional.of(userProfile));
            clientSubjectHelperMockedStatic
                    .when(() -> ClientSubjectHelper.getSubject(any(), any(), any()))
                    .thenReturn(subject);
            when(subject.getValue()).thenReturn(TEST_RP_PAIRWISE_ID);

            var detailedCounts =
                    Map.of(
                            ENTER_EMAIL, 1,
                            ENTER_PASSWORD, 2,
                            ENTER_MFA_CODE, 3);

            when(permissionDecisionManager.canReceivePassword(any(), any()))
                    .thenReturn(
                            Result.success(
                                    reauthLockedOutDecision(
                                            EXCEEDED_INCORRECT_PASSWORD_SUBMISSION_LIMIT,
                                            detailedCounts)));

            usingValidAuthSession();
            usingApplicableUserCredentialsWithLogin(SMS, true);

            var event = eventWithHeadersAndBody(VALID_HEADERS, validBodyWithReauthJourney);

            APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

            assertThat(result, hasStatus(400));
            assertThat(result, hasJsonBody(ErrorResponse.TOO_MANY_INVALID_REAUTH_ATTEMPTS));

            verifyReauthFailedReported(
                    detailedCounts, ReauthFailureReasons.INCORRECT_PASSWORD.getValue());
        }
    }

    @Test
    void shouldReturn400AndReportReauthFailureWhenUserEntersIncorrectCredentialsAndGetsLockedOut() {
        try (MockedStatic<ClientSubjectHelper> clientSubjectHelperMockedStatic =
                Mockito.mockStatic(ClientSubjectHelper.class, Mockito.CALLS_REAL_METHODS)) {
            UserProfile userProfile = generateUserProfile(null);
            when(authenticationService.getUserProfileByEmailMaybe(EMAIL))
                    .thenReturn(Optional.of(userProfile));
            clientSubjectHelperMockedStatic
                    .when(() -> ClientSubjectHelper.getSubject(any(), any(), any()))
                    .thenReturn(subject);
            when(subject.getValue()).thenReturn(TEST_RP_PAIRWISE_ID);

            var detailedCounts = Map.of(ENTER_PASSWORD, MAX_ALLOWED_RETRIES);

            when(permissionDecisionManager.canReceivePassword(any(), any()))
                    .thenReturn(Result.success(new Decision.Permitted(MAX_ALLOWED_RETRIES - 1)))
                    .thenReturn(
                            Result.success(
                                    reauthLockedOutDecision(
                                            EXCEEDED_INCORRECT_PASSWORD_SUBMISSION_LIMIT,
                                            detailedCounts)));

            usingValidAuthSession();
            usingApplicableUserCredentialsWithLogin(SMS, false);

            var event = eventWithHeadersAndBody(VALID_HEADERS, validBodyWithReauthJourney);

            APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

            assertThat(result, hasStatus(400));
            assertThat(result, hasJsonBody(ErrorResponse.TOO_MANY_INVALID_REAUTH_ATTEMPTS));

            verifyReauthFailedReported(0, MAX_ALLOWED_RETRIES, 0, "incorrect_password");
        }
    }

    private void usingValidAuthSession() {
        when(authSessionService.getSessionFromRequestHeaders(anyMap()))
                .thenReturn(
                        Optional.of(
                                new AuthSessionItem()
                                        .withSessionId(SESSION_ID)
                                        .withEmailAddress(EMAIL)
                                        .withAccountState(AuthSessionItem.AccountState.UNKNOWN)
                                        .withClientId(CLIENT_ID.getValue())
                                        .withClientName(CLIENT_NAME)
                                        .withIsSmokeTest(false)
                                        .withRpSectorIdentifierHost(SECTOR_IDENTIFIER_HOST)
                                        .withInternalCommonSubjectId(expectedCommonSubject)));
    }

    private UserCredentials usingApplicableUserCredentials(MFAMethodType mfaMethodType) {
        UserCredentials applicableUserCredentials =
                mfaMethodType.equals(SMS) ? userCredentials : userCredentialsAuthApp;
        when(authenticationService.getUserCredentialsFromEmail(EMAIL))
                .thenReturn(applicableUserCredentials);
        return applicableUserCredentials;
    }

    private UserCredentials usingApplicableUserCredentialsWithLogin(
            MFAMethodType mfaMethodType, boolean loginSuccessful) {
        UserCredentials applicableUserCredentials = usingApplicableUserCredentials(mfaMethodType);
        when(authenticationService.login(applicableUserCredentials, CommonTestVariables.PASSWORD))
                .thenReturn(loginSuccessful);
        return applicableUserCredentials;
    }

    private UserProfile generateUserProfile(String legacySubjectId) {
        return new UserProfile()
                .withEmail(EMAIL)
                .withEmailVerified(true)
                .withPhoneNumber(CommonTestVariables.UK_MOBILE_NUMBER)
                .withPhoneNumberVerified(true)
                .withPublicSubjectID(new Subject().getValue())
                .withSubjectID(INTERNAL_SUBJECT_ID.getValue())
                .withLegacySubjectID(legacySubjectId)
                .withTermsAndConditions(
                        new TermsAndConditions("1.0", NowHelper.now().toInstant().toString()));
    }

    private APIGatewayProxyRequestEvent eventWithHeadersAndBody(
            Map<String, String> headers, String body) {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setRequestContext(contextWithSourceIp(IP_ADDRESS));
        event.setHeaders(headers);
        event.setBody(body);
        return event;
    }

    private void verifyReauthFailedReported(
            int expectedEmailAttempts,
            int expectedPasswordAttemps,
            int expectedMfaAttempts,
            String expectedFailureReason) {
        verify(auditService, times(1))
                .submitAuditEvent(
                        FrontendAuditableEvent.AUTH_REAUTH_FAILED,
                        auditContextWithAllUserInfo.withTxmaAuditEncoded(ENCODED_DEVICE_DETAILS),
                        pair("rpPairwiseId", TEST_RP_PAIRWISE_ID),
                        pair("incorrect_email_attempt_count", expectedEmailAttempts),
                        pair("incorrect_password_attempt_count", expectedPasswordAttemps),
                        pair("incorrect_otp_code_attempt_count", expectedMfaAttempts),
                        pair("failure-reason", expectedFailureReason));
        var expectedDimensions =
                Map.ofEntries(
                        Map.entry(ENVIRONMENT.getValue(), configurationService.getEnvironment()),
                        Map.entry(FAILURE_REASON.getValue(), expectedFailureReason));
        verify(cloudwatchMetricsService)
                .incrementCounter(CloudwatchMetrics.REAUTH_FAILED.getValue(), expectedDimensions);
    }

    private void verifyReauthFailedReported(
            Map<CountType, Integer> detailedCounts, String expectedFailureReason) {
        verifyReauthFailedReported(
                detailedCounts.get(ENTER_EMAIL),
                detailedCounts.get(ENTER_PASSWORD),
                detailedCounts.get(ENTER_MFA_CODE),
                expectedFailureReason);
    }

    private Decision reauthLockedOutDecision(
            ForbiddenReason reason, Map<CountType, Integer> detailedCounts) {
        return new Decision.ReauthLockedOut(
                reason,
                MAX_ALLOWED_RETRIES,
                Instant.now().plusSeconds(900),
                false,
                detailedCounts,
                java.util.List.of(ENTER_EMAIL));
    }
}
