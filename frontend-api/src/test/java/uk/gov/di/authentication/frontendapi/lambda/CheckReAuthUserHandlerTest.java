package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent;
import uk.gov.di.authentication.frontendapi.entity.CheckReauthUserRequest;
import uk.gov.di.authentication.shared.domain.CloudwatchMetrics;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.entity.CountType;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.helpers.SaltHelper;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthSessionService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.state.UserContext;
import uk.gov.di.authentication.userpermissions.PermissionDecisionManager;
import uk.gov.di.authentication.userpermissions.UserActionsManager;
import uk.gov.di.authentication.userpermissions.entity.Decision;
import uk.gov.di.authentication.userpermissions.entity.ForbiddenReason;
import uk.gov.di.authentication.userpermissions.entity.PermissionContext;
import uk.gov.di.authentication.userpermissions.entity.TrackingError;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.frontendapi.helpers.ApiGatewayProxyRequestHelper.apiRequestEventWithHeadersAndBody;
import static uk.gov.di.authentication.shared.domain.CloudwatchMetricDimensions.ENVIRONMENT;
import static uk.gov.di.authentication.shared.domain.CloudwatchMetricDimensions.FAILURE_REASON;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.CLIENT_SESSION_ID;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.DI_PERSISTENT_SESSION_ID;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.ENCODED_DEVICE_DETAILS;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.IP_ADDRESS;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.SESSION_ID;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.VALID_HEADERS;
import static uk.gov.di.authentication.shared.services.AuditService.MetadataPair.pair;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;

class CheckReAuthUserHandlerTest {
    private final AuthenticationService authenticationService = mock(AuthenticationService.class);
    private final AuditService auditService = mock(AuditService.class);
    private final Context context = mock(Context.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final CloudwatchMetricsService cloudwatchMetricsService =
            mock(CloudwatchMetricsService.class);
    private final AuthSessionService authSessionService = mock(AuthSessionService.class);
    private final UserActionsManager userActionsManager = mock(UserActionsManager.class);
    private final PermissionDecisionManager permissionDecisionManager =
            mock(PermissionDecisionManager.class);

    private static final String CLIENT_ID = "test-client-id";
    private static final String EMAIL_USED_TO_SIGN_IN = "joe.bloggs@digital.cabinet-office.gov.uk";
    private static final String DIFFERENT_EMAIL_USED_TO_REAUTHENTICATE =
            "not.signedin.email@digital.cabinet-office.gov.uk";
    private static final String TEST_SUBJECT_ID = "subject-id";
    private static final String DIFFERENT_SUBJECT_ID = "DIFFERENT_SUBJECT_ID";
    private static final String SECTOR_IDENTIFIER_HOST = "example.com";
    private static final String TEST_RP_PAIRWISE_ID = "TEST_RP_PAIRWISE_ID";
    private static final UserProfile USER_PROFILE =
            new UserProfile()
                    .withEmail(EMAIL_USED_TO_SIGN_IN)
                    .withEmailVerified(true)
                    .withPhoneNumberVerified(true)
                    .withPublicSubjectID(new Subject().getValue())
                    .withSubjectID(TEST_SUBJECT_ID);

    // Here the body doesn't matter, as the method we're testing already assumes we've extracted
    // the body into the relevant request object
    private static final APIGatewayProxyRequestEvent API_REQUEST_EVENT_WITH_VALID_HEADERS =
            apiRequestEventWithHeadersAndBody(VALID_HEADERS, null);

    private final AuthSessionItem authSession =
            new AuthSessionItem()
                    .withSessionId(SESSION_ID)
                    .withEmailAddress(EMAIL_USED_TO_SIGN_IN)
                    .withClientId(CLIENT_ID)
                    .withRpSectorIdentifierHost(SECTOR_IDENTIFIER_HOST)
                    .withInternalCommonSubjectId(TEST_SUBJECT_ID);

    private final AuditContext testAuditContextWithoutAuditEncoded =
            new AuditContext(
                    CLIENT_ID,
                    CLIENT_SESSION_ID,
                    SESSION_ID,
                    TEST_SUBJECT_ID,
                    EMAIL_USED_TO_SIGN_IN,
                    IP_ADDRESS,
                    AuditService.UNKNOWN,
                    DI_PERSISTENT_SESSION_ID,
                    Optional.empty(),
                    new ArrayList<>());

    private final AuditContext testAuditContextWithAuditEncoded =
            testAuditContextWithoutAuditEncoded.withTxmaAuditEncoded(
                    Optional.of(ENCODED_DEVICE_DETAILS));

    private final UserContext userContext = mock(UserContext.class);

    private String expectedRpPairwiseSub;

    private static final byte[] SALT = SaltHelper.generateNewSalt();

    private CheckReAuthUserHandler handler;

    private static final int MAX_RETRIES = 6;

    @BeforeEach
    public void setUp() {
        when(authenticationService.getUserProfileByEmailMaybe(EMAIL_USED_TO_SIGN_IN))
                .thenReturn(Optional.of(USER_PROFILE));
        when(authenticationService.getUserProfileByEmail(EMAIL_USED_TO_SIGN_IN))
                .thenReturn(USER_PROFILE);
        when(authenticationService.getOrGenerateSalt(any(UserProfile.class))).thenReturn(SALT);

        when(userContext.getAuthSession()).thenReturn(authSession);
        when(userContext.getClientSessionId()).thenReturn(CLIENT_SESSION_ID);
        when(userContext.getTxmaAuditEncoded()).thenReturn(ENCODED_DEVICE_DETAILS);
        when(userContext.getUserProfile()).thenReturn(Optional.of(USER_PROFILE));

        when(configurationService.getEnvironment()).thenReturn("test");
        when(configurationService.getMaxEmailReAuthRetries()).thenReturn(MAX_RETRIES);
        when(configurationService.getMaxPasswordRetries()).thenReturn(MAX_RETRIES);
        when(configurationService.getCodeMaxRetries()).thenReturn(MAX_RETRIES);
        when(configurationService.supportReauthSignoutEnabled()).thenReturn(true);

        when(permissionDecisionManager.canReceiveEmailAddress(any(), any()))
                .thenReturn(Result.success(new Decision.Permitted(0)));

        when(userActionsManager.incorrectEmailAddressReceived(any(), any()))
                .thenReturn(Result.success(null));

        expectedRpPairwiseSub =
                ClientSubjectHelper.getSubject(USER_PROFILE, authSession, authenticationService)
                        .getValue();

        handler =
                new CheckReAuthUserHandler(
                        configurationService,
                        authenticationService,
                        auditService,
                        cloudwatchMetricsService,
                        authSessionService,
                        userActionsManager,
                        permissionDecisionManager);
    }

    @Test
    void shouldReturn200ForSuccessfulReAuthRequest() {
        var existingCountOfIncorrectEmails = 1;
        setupExistingEnterEmailAttemptsCountForIdentifier(existingCountOfIncorrectEmails);

        var result =
                handler.handleRequestWithUserContext(
                        API_REQUEST_EVENT_WITH_VALID_HEADERS,
                        context,
                        new CheckReauthUserRequest(EMAIL_USED_TO_SIGN_IN, expectedRpPairwiseSub),
                        userContext);

        assertEquals(200, result.getStatusCode());

        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.AUTH_REAUTH_ACCOUNT_IDENTIFIED,
                        testAuditContextWithAuditEncoded,
                        pair("rpPairwiseId", expectedRpPairwiseSub),
                        pair("incorrect_email_attempt_count", existingCountOfIncorrectEmails));

        verify(authenticationService, atLeastOnce())
                .getUserProfileByEmailMaybe(EMAIL_USED_TO_SIGN_IN);
    }

    @Test
    void shouldReturn404ForWhenUserNotFound() {
        when(authenticationService.getUserProfileByEmailMaybe(EMAIL_USED_TO_SIGN_IN))
                .thenReturn(Optional.empty());

        setupExistingEnterEmailAttemptsCountForIdentifier(1);

        var result =
                handler.handleRequestWithUserContext(
                        API_REQUEST_EVENT_WITH_VALID_HEADERS,
                        context,
                        new CheckReauthUserRequest(EMAIL_USED_TO_SIGN_IN, TEST_RP_PAIRWISE_ID),
                        userContext);

        assertEquals(404, result.getStatusCode());
        assertThat(result, hasJsonBody(ErrorResponse.USER_NOT_FOUND));

        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.AUTH_REAUTH_INCORRECT_EMAIL_ENTERED,
                        testAuditContextWithAuditEncoded,
                        pair("rpPairwiseId", TEST_RP_PAIRWISE_ID),
                        pair("incorrect_email_attempt_count", 1),
                        pair("user_supplied_email", EMAIL_USED_TO_SIGN_IN, true));
    }

    @Test
    void shouldReturn400WhenUserHasBeenBlockedForPasswordRetries() {
        when(permissionDecisionManager.canReceiveEmailAddress(any(), any()))
                .thenReturn(
                        Result.success(
                                new Decision.ReauthLockedOut(
                                        ForbiddenReason
                                                .EXCEEDED_INCORRECT_PASSWORD_SUBMISSION_LIMIT,
                                        MAX_RETRIES,
                                        null,
                                        false,
                                        Map.of(CountType.ENTER_PASSWORD, MAX_RETRIES),
                                        List.of(CountType.ENTER_PASSWORD))));

        var result =
                handler.handleRequestWithUserContext(
                        API_REQUEST_EVENT_WITH_VALID_HEADERS,
                        context,
                        new CheckReauthUserRequest(EMAIL_USED_TO_SIGN_IN, expectedRpPairwiseSub),
                        userContext);

        assertEquals(400, result.getStatusCode());
        assertThat(result, hasJsonBody(ErrorResponse.TOO_MANY_INVALID_REAUTH_ATTEMPTS));
    }

    @Test
    void shouldReturn400WhenUserHasBeenBlockedForMfaAttempts() {
        when(permissionDecisionManager.canReceiveEmailAddress(any(), any()))
                .thenReturn(
                        Result.success(
                                new Decision.ReauthLockedOut(
                                        ForbiddenReason.EXCEEDED_INCORRECT_MFA_OTP_SUBMISSION_LIMIT,
                                        MAX_RETRIES,
                                        null,
                                        false,
                                        Map.of(CountType.ENTER_MFA_CODE, MAX_RETRIES),
                                        List.of(CountType.ENTER_MFA_CODE))));

        var result =
                handler.handleRequestWithUserContext(
                        API_REQUEST_EVENT_WITH_VALID_HEADERS,
                        context,
                        new CheckReauthUserRequest(EMAIL_USED_TO_SIGN_IN, expectedRpPairwiseSub),
                        userContext);

        assertEquals(400, result.getStatusCode());
        assertThat(result, hasJsonBody(ErrorResponse.TOO_MANY_INVALID_REAUTH_ATTEMPTS));
    }

    @Test
    void shouldReturn500WhenPermissionDecisionManagerReturnsError() {
        when(permissionDecisionManager.canReceiveEmailAddress(any(), any()))
                .thenReturn(
                        Result.failure(
                                uk.gov.di.authentication.userpermissions.entity.DecisionError
                                        .STORAGE_SERVICE_ERROR));

        var result =
                handler.handleRequestWithUserContext(
                        API_REQUEST_EVENT_WITH_VALID_HEADERS,
                        context,
                        new CheckReauthUserRequest(EMAIL_USED_TO_SIGN_IN, expectedRpPairwiseSub),
                        userContext);

        assertEquals(500, result.getStatusCode());
        assertThat(result, hasJsonBody(ErrorResponse.STORAGE_LAYER_ERROR));
    }

    @Test
    void shouldReturn404ForWhenUserDoesNotMatch() {
        setupExistingEnterEmailAttemptsCountForIdentifier(3);

        var result =
                handler.handleRequestWithUserContext(
                        API_REQUEST_EVENT_WITH_VALID_HEADERS,
                        context,
                        new CheckReauthUserRequest(
                                DIFFERENT_EMAIL_USED_TO_REAUTHENTICATE, TEST_RP_PAIRWISE_ID),
                        userContext);

        assertEquals(404, result.getStatusCode());
        assertThat(result, hasJsonBody(ErrorResponse.USER_NOT_FOUND));

        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.AUTH_REAUTH_INCORRECT_EMAIL_ENTERED,
                        testAuditContextWithAuditEncoded,
                        pair("rpPairwiseId", TEST_RP_PAIRWISE_ID),
                        pair("incorrect_email_attempt_count", 3),
                        pair("user_supplied_email", DIFFERENT_EMAIL_USED_TO_REAUTHENTICATE, true));
    }

    @Test
    void shouldIncludeTheUserSubjectIdForWhenUserDoesNotMatchButHasAccount() {
        setupExistingEnterEmailAttemptsCountForIdentifier(3);
        when(authenticationService.getUserProfileByEmailMaybe(
                        DIFFERENT_EMAIL_USED_TO_REAUTHENTICATE))
                .thenReturn(Optional.of(new UserProfile().withSubjectID(DIFFERENT_SUBJECT_ID)));

        var result =
                handler.handleRequestWithUserContext(
                        API_REQUEST_EVENT_WITH_VALID_HEADERS,
                        context,
                        new CheckReauthUserRequest(
                                DIFFERENT_EMAIL_USED_TO_REAUTHENTICATE, TEST_RP_PAIRWISE_ID),
                        userContext);

        assertEquals(404, result.getStatusCode());
        assertThat(result, hasJsonBody(ErrorResponse.USER_NOT_FOUND));

        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.AUTH_REAUTH_INCORRECT_EMAIL_ENTERED,
                        testAuditContextWithAuditEncoded,
                        pair("rpPairwiseId", TEST_RP_PAIRWISE_ID),
                        pair("incorrect_email_attempt_count", 3),
                        pair("user_supplied_email", DIFFERENT_EMAIL_USED_TO_REAUTHENTICATE, true),
                        pair("user_id_for_user_supplied_email", DIFFERENT_SUBJECT_ID, true));
    }

    @Test
    void
            shouldUseTheRpPairwiseIdWhenThereIsAnErrorAndThereIsNoUserProfileForTheEmailUsedToSignIn() {
        when(authenticationService.getUserProfileByEmailMaybe(EMAIL_USED_TO_SIGN_IN))
                .thenReturn(Optional.empty());

        setupExistingEnterEmailAttemptsCountForIdentifier(1);

        when(authenticationService.getUserProfileByEmail(EMAIL_USED_TO_SIGN_IN)).thenReturn(null);

        var result =
                handler.handleRequestWithUserContext(
                        API_REQUEST_EVENT_WITH_VALID_HEADERS,
                        context,
                        new CheckReauthUserRequest(EMAIL_USED_TO_SIGN_IN, TEST_RP_PAIRWISE_ID),
                        userContext);

        assertEquals(404, result.getStatusCode());
        assertThat(result, hasJsonBody(ErrorResponse.USER_NOT_FOUND));

        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.AUTH_REAUTH_INCORRECT_EMAIL_ENTERED,
                        testAuditContextWithAuditEncoded,
                        pair("rpPairwiseId", TEST_RP_PAIRWISE_ID),
                        pair("incorrect_email_attempt_count", 1),
                        pair("user_supplied_email", EMAIL_USED_TO_SIGN_IN, true));
    }

    private void setupExistingEnterEmailAttemptsCountForIdentifier(int count) {
        when(permissionDecisionManager.canReceiveEmailAddress(any(), any()))
                .thenReturn(Result.success(new Decision.Permitted(count)));
    }

    @Test
    void shouldRecordIncorrectEmailReceived() {
        setupExistingEnterEmailAttemptsCountForIdentifier(0);

        handler.handleRequestWithUserContext(
                API_REQUEST_EVENT_WITH_VALID_HEADERS,
                context,
                new CheckReauthUserRequest(EMAIL_USED_TO_SIGN_IN, TEST_RP_PAIRWISE_ID),
                userContext);

        verify(userActionsManager)
                .incorrectEmailAddressReceived(
                        eq(JourneyType.REAUTHENTICATION), any(PermissionContext.class));
    }

    @Test
    void shouldReturn500WhenIncorrectEmailTrackingFails() {
        when(userActionsManager.incorrectEmailAddressReceived(any(), any()))
                .thenReturn(Result.failure(TrackingError.STORAGE_SERVICE_ERROR));

        var result =
                handler.handleRequestWithUserContext(
                        API_REQUEST_EVENT_WITH_VALID_HEADERS,
                        context,
                        new CheckReauthUserRequest(EMAIL_USED_TO_SIGN_IN, TEST_RP_PAIRWISE_ID),
                        userContext);

        assertEquals(500, result.getStatusCode());
        assertThat(result, hasJsonBody(ErrorResponse.STORAGE_LAYER_ERROR));
    }

    @Test
    void shouldReturn400WhenIncorrectEmailTriggersLockout() {
        when(permissionDecisionManager.canReceiveEmailAddress(any(), any()))
                .thenReturn(Result.success(new Decision.Permitted(MAX_RETRIES - 1)))
                .thenReturn(
                        Result.success(
                                new Decision.ReauthLockedOut(
                                        ForbiddenReason
                                                .EXCEEDED_INCORRECT_EMAIL_ADDRESS_SUBMISSION_LIMIT,
                                        MAX_RETRIES,
                                        null,
                                        false,
                                        Map.of(CountType.ENTER_EMAIL, MAX_RETRIES),
                                        List.of(CountType.ENTER_EMAIL))));

        var result =
                handler.handleRequestWithUserContext(
                        API_REQUEST_EVENT_WITH_VALID_HEADERS,
                        context,
                        new CheckReauthUserRequest(EMAIL_USED_TO_SIGN_IN, TEST_RP_PAIRWISE_ID),
                        userContext);

        assertEquals(400, result.getStatusCode());
        assertThat(result, hasJsonBody(ErrorResponse.TOO_MANY_INVALID_REAUTH_ATTEMPTS));
    }

    @TestFactory
    Stream<DynamicTest> emailSubmittedLockoutCheckScenarios() {
        var differentUserProfile =
                new UserProfile()
                        .withEmail(DIFFERENT_EMAIL_USED_TO_REAUTHENTICATE)
                        .withSubjectID(DIFFERENT_SUBJECT_ID);

        enum LockoutLocation {
            USER_PROFILE_ASSOCIATED_WITH_RP_SUBMITTED_PAIRWISE_ID,
            DIFFERENT_USER_PROFILE,
            RP_SUBMITTED_PAIRWISE_ID,
            DIFFERENT_RP_PAIRWISE_ID
        }

        enum SignedInState {
            NOT_SIGNED_IN,
            TO_USER_PROFILE_ASSOCIATED_WITH_RP_SUBMITTED_PAIRWISE_ID,
            TO_DIFFERENT_USER_PROFILE
        }

        enum UserSubmittedEmail {
            EMAIL_ASSOCIATED_WITH_RP_SUBMITTED_PAIRWISE_ID,
            DIFFERENT_EMAIL
        }

        interface AuditVerifier {
            void verify(AuditService auditService);
        }

        interface MetricsVerifier {
            void verify(CloudwatchMetricsService cloudwatchMetricsService);
        }

        record Scenario(
                LockoutLocation lockoutLocation,
                SignedInState signedInState,
                UserSubmittedEmail userSubmittedEmail,
                int expectedStatusCode,
                ErrorResponse expectedErrorResponse,
                AuditVerifier auditVerifier,
                MetricsVerifier metricsVerifier) {
            String description() {
                return String.format(
                        "%s + %s + %s = %d %s",
                        lockoutLocation.name(),
                        signedInState.name(),
                        userSubmittedEmail.name(),
                        expectedStatusCode,
                        expectedErrorResponse != null ? expectedErrorResponse.name() : "SUCCESS");
            }

            void setupMocks(
                    PermissionDecisionManager permissionDecisionManager,
                    String expectedRpPairwiseSub) {
                int testSubjectIdCount = 0;
                int expectedRpPairwiseCount = 0;
                int differentSubjectIdCount = 0;

                switch (lockoutLocation) {
                    case USER_PROFILE_ASSOCIATED_WITH_RP_SUBMITTED_PAIRWISE_ID -> testSubjectIdCount =
                            MAX_RETRIES;
                    case RP_SUBMITTED_PAIRWISE_ID -> expectedRpPairwiseCount = MAX_RETRIES;
                    case DIFFERENT_USER_PROFILE -> differentSubjectIdCount = MAX_RETRIES;
                }

                record MockSetup(List<String> subjectIds, String rpPairwiseId, int count) {}

                var mockCountsByJourneySetups =
                        List.of(
                                new MockSetup(
                                        Arrays.asList(null, null),
                                        expectedRpPairwiseSub,
                                        expectedRpPairwiseCount),
                                new MockSetup(
                                        Arrays.asList(TEST_SUBJECT_ID, TEST_SUBJECT_ID),
                                        expectedRpPairwiseSub,
                                        testSubjectIdCount + expectedRpPairwiseCount),
                                new MockSetup(
                                        Arrays.asList(TEST_SUBJECT_ID, null),
                                        expectedRpPairwiseSub,
                                        testSubjectIdCount + expectedRpPairwiseCount),
                                new MockSetup(
                                        Arrays.asList(null, TEST_SUBJECT_ID),
                                        expectedRpPairwiseSub,
                                        testSubjectIdCount + expectedRpPairwiseCount),
                                new MockSetup(
                                        Arrays.asList(null, DIFFERENT_SUBJECT_ID),
                                        expectedRpPairwiseSub,
                                        differentSubjectIdCount + expectedRpPairwiseCount),
                                new MockSetup(
                                        Arrays.asList(TEST_SUBJECT_ID, DIFFERENT_SUBJECT_ID),
                                        expectedRpPairwiseSub,
                                        testSubjectIdCount
                                                + differentSubjectIdCount
                                                + expectedRpPairwiseCount));

                for (var setup : mockCountsByJourneySetups) {
                    when(permissionDecisionManager.canReceiveEmailAddress(
                                    JourneyType.REAUTHENTICATION,
                                    PermissionContext.builder()
                                            .withInternalSubjectIds(setup.subjectIds)
                                            .withRpPairwiseId(setup.rpPairwiseId)
                                            .build()))
                            .thenReturn(
                                    Result.success(
                                            setup.count >= MAX_RETRIES
                                                    ? new Decision.ReauthLockedOut(
                                                            ForbiddenReason
                                                                    .EXCEEDED_INCORRECT_EMAIL_ADDRESS_SUBMISSION_LIMIT,
                                                            setup.count,
                                                            Instant.now(),
                                                            false,
                                                            Map.of(
                                                                    CountType.ENTER_EMAIL,
                                                                    setup.count),
                                                            List.of(CountType.ENTER_EMAIL))
                                                    : new Decision.Permitted(setup.count)));
                }
            }
        }

        interface ScenarioCreator {
            Scenario create(
                    LockoutLocation lockout, SignedInState signedIn, UserSubmittedEmail email);
        }

        ScenarioCreator createScenario =
                (lockout, signedIn, email) -> {
                    var differentEmailSubmitted = email.equals(UserSubmittedEmail.DIFFERENT_EMAIL);

                    var lockoutOnRpPairwiseId =
                            lockout.equals(LockoutLocation.RP_SUBMITTED_PAIRWISE_ID);

                    var lockoutOnUserProfileAndSignedInToThatProfile =
                            lockout.equals(
                                            LockoutLocation
                                                    .USER_PROFILE_ASSOCIATED_WITH_RP_SUBMITTED_PAIRWISE_ID)
                                    && signedIn.equals(
                                            SignedInState
                                                    .TO_USER_PROFILE_ASSOCIATED_WITH_RP_SUBMITTED_PAIRWISE_ID);

                    var lockoutOnUserProfileAndSubmittedEmailForThatProfile =
                            lockout.equals(
                                            LockoutLocation
                                                    .USER_PROFILE_ASSOCIATED_WITH_RP_SUBMITTED_PAIRWISE_ID)
                                    && email.equals(
                                            UserSubmittedEmail
                                                    .EMAIL_ASSOCIATED_WITH_RP_SUBMITTED_PAIRWISE_ID);

                    var lockoutOnDifferentUserProfileAndSignedInToThatProfile =
                            lockout.equals(LockoutLocation.DIFFERENT_USER_PROFILE)
                                    && signedIn.equals(SignedInState.TO_DIFFERENT_USER_PROFILE);

                    var shouldExpectLockout =
                            lockoutOnRpPairwiseId
                                    || lockoutOnUserProfileAndSignedInToThatProfile
                                    || lockoutOnUserProfileAndSubmittedEmailForThatProfile
                                    || lockoutOnDifferentUserProfileAndSignedInToThatProfile;

                    int expectedStatusCode;
                    ErrorResponse expectedErrorResponse;
                    AuditVerifier auditVerifier = null;
                    MetricsVerifier metricsVerifier = null;

                    if (shouldExpectLockout) {
                        expectedStatusCode = 400;
                        expectedErrorResponse = ErrorResponse.TOO_MANY_INVALID_REAUTH_ATTEMPTS;
                        auditVerifier =
                                auditSvc -> {
                                    verify(auditSvc, never())
                                            .submitAuditEvent(
                                                    eq(
                                                            FrontendAuditableEvent
                                                                    .AUTH_REAUTH_INCORRECT_EMAIL_LIMIT_BREACHED),
                                                    any(),
                                                    any(AuditService.MetadataPair[].class));
                                    verify(auditSvc, times(1))
                                            .submitAuditEvent(
                                                    FrontendAuditableEvent.AUTH_REAUTH_FAILED,
                                                    testAuditContextWithAuditEncoded,
                                                    AuditService.MetadataPair.pair(
                                                            "rpPairwiseId", expectedRpPairwiseSub),
                                                    AuditService.MetadataPair.pair(
                                                            "incorrect_email_attempt_count", 6),
                                                    AuditService.MetadataPair.pair(
                                                            "incorrect_password_attempt_count", 0),
                                                    AuditService.MetadataPair.pair(
                                                            "incorrect_otp_code_attempt_count", 0),
                                                    AuditService.MetadataPair.pair(
                                                            "failure-reason", "incorrect_email"));
                                };
                        metricsVerifier =
                                metricsSvc ->
                                        verify(metricsSvc)
                                                .incrementCounter(
                                                        CloudwatchMetrics.REAUTH_FAILED.getValue(),
                                                        Map.of(
                                                                ENVIRONMENT.getValue(),
                                                                configurationService
                                                                        .getEnvironment(),
                                                                FAILURE_REASON.getValue(),
                                                                "incorrect_email"));
                    } else if (differentEmailSubmitted) {
                        expectedStatusCode = 404;
                        expectedErrorResponse = ErrorResponse.USER_NOT_FOUND;
                    } else {
                        expectedStatusCode = 200;
                        expectedErrorResponse = null;
                    }

                    return new Scenario(
                            lockout,
                            signedIn,
                            email,
                            expectedStatusCode,
                            expectedErrorResponse,
                            auditVerifier,
                            metricsVerifier);
                };

        var scenarios =
                Stream.of(LockoutLocation.values())
                        .flatMap(
                                lockout ->
                                        Stream.of(SignedInState.values())
                                                .flatMap(
                                                        signedIn ->
                                                                Stream.of(
                                                                                UserSubmittedEmail
                                                                                        .values())
                                                                        .map(
                                                                                email ->
                                                                                        createScenario
                                                                                                .create(
                                                                                                        lockout,
                                                                                                        signedIn,
                                                                                                        email))));

        return scenarios.map(
                scenario ->
                        DynamicTest.dynamicTest(
                                scenario.description(),
                                () -> {
                                    reset(auditService, cloudwatchMetricsService);

                                    when(userContext.getUserProfile())
                                            .thenReturn(
                                                    switch (scenario.signedInState) {
                                                        case NOT_SIGNED_IN -> Optional.empty();
                                                        case TO_USER_PROFILE_ASSOCIATED_WITH_RP_SUBMITTED_PAIRWISE_ID -> Optional
                                                                .of(USER_PROFILE);
                                                        case TO_DIFFERENT_USER_PROFILE -> Optional
                                                                .of(differentUserProfile);
                                                    });

                                    when(authenticationService.getUserProfileByEmailMaybe(
                                                    USER_PROFILE.getEmail()))
                                            .thenReturn(Optional.of(USER_PROFILE));

                                    when(authenticationService.getUserProfileByEmailMaybe(
                                                    differentUserProfile.getEmail()))
                                            .thenReturn(Optional.of(differentUserProfile));

                                    scenario.setupMocks(
                                            permissionDecisionManager, expectedRpPairwiseSub);

                                    var result =
                                            handler.handleRequestWithUserContext(
                                                    API_REQUEST_EVENT_WITH_VALID_HEADERS,
                                                    context,
                                                    new CheckReauthUserRequest(
                                                            scenario.userSubmittedEmail
                                                                            == UserSubmittedEmail
                                                                                    .EMAIL_ASSOCIATED_WITH_RP_SUBMITTED_PAIRWISE_ID
                                                                    ? USER_PROFILE.getEmail()
                                                                    : differentUserProfile
                                                                            .getEmail(),
                                                            expectedRpPairwiseSub),
                                                    userContext);

                                    assertEquals(
                                            scenario.expectedStatusCode,
                                            result.getStatusCode(),
                                            "Status code mismatch for scenario: "
                                                    + scenario.description());

                                    if (scenario.expectedErrorResponse != null) {
                                        assertThat(
                                                result,
                                                hasJsonBody(scenario.expectedErrorResponse));
                                    }

                                    if (scenario.auditVerifier != null) {
                                        scenario.auditVerifier.verify(auditService);
                                    }

                                    if (scenario.metricsVerifier != null) {
                                        scenario.metricsVerifier.verify(cloudwatchMetricsService);
                                    }
                                }));
    }
}
