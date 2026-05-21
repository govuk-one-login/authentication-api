package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent;
import uk.gov.di.authentication.frontendapi.entity.MfaResetType;
import uk.gov.di.authentication.frontendapi.entity.ReauthFailureReasons;
import uk.gov.di.authentication.shared.domain.CloudwatchMetrics;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.entity.CodeRequestType;
import uk.gov.di.authentication.shared.entity.CountType;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.NotificationType;
import uk.gov.di.authentication.shared.entity.PriorityIdentifier;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethod;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.helpers.SaltHelper;
import uk.gov.di.authentication.shared.helpers.TestUserHelper;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthSessionService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoAccountModifiersService;
import uk.gov.di.authentication.shared.services.mfa.MFAMethodsService;
import uk.gov.di.authentication.shared.services.mfa.MfaRetrieveFailureReason;
import uk.gov.di.authentication.shared.state.UserContext;
import uk.gov.di.authentication.sharedtest.logging.CaptureLoggingExtension;
import uk.gov.di.authentication.userpermissions.PermissionDecisionManager;
import uk.gov.di.authentication.userpermissions.UserActionsManager;
import uk.gov.di.authentication.userpermissions.entity.Decision;
import uk.gov.di.authentication.userpermissions.entity.DecisionError;
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

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.frontendapi.helpers.ApiGatewayProxyRequestHelper.apiRequestEventWithHeadersAndBody;
import static uk.gov.di.authentication.shared.domain.AuditableEvent.AUDIT_EVENT_EXTENSIONS_JOURNEY_TYPE;
import static uk.gov.di.authentication.shared.domain.AuditableEvent.AUDIT_EVENT_EXTENSIONS_MFA_METHOD;
import static uk.gov.di.authentication.shared.domain.AuditableEvent.AUDIT_EVENT_EXTENSIONS_MFA_RESET_TYPE;
import static uk.gov.di.authentication.shared.domain.AuditableEvent.AUDIT_EVENT_EXTENSIONS_PHONE_NUMBER_COUNTRY_CODE;
import static uk.gov.di.authentication.shared.domain.CloudwatchMetricDimensions.ENVIRONMENT;
import static uk.gov.di.authentication.shared.domain.CloudwatchMetricDimensions.FAILURE_REASON;
import static uk.gov.di.authentication.shared.domain.CloudwatchMetricDimensions.MFA_RESET_TYPE;
import static uk.gov.di.authentication.shared.domain.CloudwatchMetrics.FORCED_MFA_RESET_INITIATED;
import static uk.gov.di.authentication.shared.entity.CountType.ENTER_EMAIL;
import static uk.gov.di.authentication.shared.entity.CountType.ENTER_MFA_CODE;
import static uk.gov.di.authentication.shared.entity.CountType.ENTER_PASSWORD;
import static uk.gov.di.authentication.shared.entity.CredentialTrustLevel.MEDIUM_LEVEL;
import static uk.gov.di.authentication.shared.entity.JourneyType.ACCOUNT_RECOVERY;
import static uk.gov.di.authentication.shared.entity.JourneyType.REAUTHENTICATION;
import static uk.gov.di.authentication.shared.entity.JourneyType.REGISTRATION;
import static uk.gov.di.authentication.shared.entity.JourneyType.SIGN_IN;
import static uk.gov.di.authentication.shared.entity.NotificationType.MFA_SMS;
import static uk.gov.di.authentication.shared.entity.NotificationType.RESET_PASSWORD_WITH_CODE;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_CHANGE_HOW_GET_SECURITY_CODES;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_EMAIL;
import static uk.gov.di.authentication.shared.services.AuditService.MetadataPair.pair;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.BACKUP_SMS_METHOD;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.CLIENT_SESSION_ID;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.DEFAULT_SMS_METHOD;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.DI_PERSISTENT_SESSION_ID;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.EMAIL;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.ENCODED_DEVICE_DETAILS;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.INTERNAL_COMMON_SUBJECT_ID;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.INTERNATIONAL_MOBILE_NUMBER;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.IP_ADDRESS;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.SESSION_ID;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.VALID_HEADERS;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.VALID_HEADERS_WITHOUT_AUDIT_ENCODED;
import static uk.gov.di.authentication.sharedtest.logging.LogEventMatcher.withMessageContaining;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class VerifyCodeHandlerTest {

    private static final String CODE = "123456";
    private static final String INVALID_CODE = "6543221";
    private static final String CLIENT_ID = "client-id";
    private static final String CLIENT_NAME = "client-name";
    private static final String TEST_CLIENT_ID = "test-client-id";
    private static final String CLIENT_SECTOR_HOST = "client.test.account.gov.uk";
    private static final String TEST_CLIENT_CODE = "654321";
    private static final String TEST_CLIENT_EMAIL =
            "testclient.user1@digital.cabinet-office.gov.uk";
    private static final String SECTOR_HOST = "test.account.gov.uk";
    private static final byte[] SALT = SaltHelper.generateNewSalt();
    private static final String TEST_SUBJECT_ID = "test-subject-id";
    private static final long CODE_EXPIRY_TIME = 900;
    private static final int MAX_RETRIES = 6;
    private final Context context = mock(Context.class);
    private final CodeStorageService codeStorageService = mock(CodeStorageService.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final UserProfile userProfile = mock(UserProfile.class);
    private final AuthSessionItem authSession =
            new AuthSessionItem()
                    .withSessionId(SESSION_ID)
                    .withEmailAddress(EMAIL)
                    .withInternalCommonSubjectId(INTERNAL_COMMON_SUBJECT_ID)
                    .withClientId(CLIENT_ID)
                    .withClientName(CLIENT_NAME)
                    .withRpSectorIdentifierHost(CLIENT_SECTOR_HOST);
    private final AuthenticationService authenticationService = mock(AuthenticationService.class);
    private final AuditService auditService = mock(AuditService.class);
    private final CloudwatchMetricsService cloudwatchMetricsService =
            mock(CloudwatchMetricsService.class);
    private final DynamoAccountModifiersService accountModifiersService =
            mock(DynamoAccountModifiersService.class);
    private final AuthSessionService authSessionService = mock(AuthSessionService.class);
    private final MFAMethodsService mfaMethodsService = mock(MFAMethodsService.class);
    private final UserActionsManager userActionsManager = mock(UserActionsManager.class);
    private final PermissionDecisionManager permissionDecisionManager =
            mock(PermissionDecisionManager.class);
    private final TestUserHelper testUserHelper = mock(TestUserHelper.class);

    private final AuditContext AUDIT_CONTEXT =
            new AuditContext(
                    CLIENT_ID,
                    CLIENT_SESSION_ID,
                    SESSION_ID,
                    INTERNAL_COMMON_SUBJECT_ID,
                    EMAIL,
                    IP_ADDRESS,
                    AuditService.UNKNOWN,
                    DI_PERSISTENT_SESSION_ID,
                    Optional.of(ENCODED_DEVICE_DETAILS),
                    new ArrayList<>());

    private final AuditContext AUDIT_CONTEXT_FOR_TEST_CLIENT =
            AUDIT_CONTEXT.withSessionId(authSession.getSessionId()).withClientId(TEST_CLIENT_ID);

    private VerifyCodeHandler handler;

    @RegisterExtension
    private final CaptureLoggingExtension logging =
            new CaptureLoggingExtension(VerifyCodeHandler.class);

    @AfterEach
    void tearDown() {
        assertThat(
                logging.events(),
                not(hasItem(withMessageContaining(CLIENT_ID, TEST_CLIENT_CODE, SESSION_ID))));
    }

    @BeforeEach
    void setup() {
        handler =
                new VerifyCodeHandler(
                        configurationService,
                        authenticationService,
                        codeStorageService,
                        auditService,
                        cloudwatchMetricsService,
                        accountModifiersService,
                        authSessionService,
                        mfaMethodsService,
                        userActionsManager,
                        permissionDecisionManager,
                        testUserHelper);

        when(authenticationService.getUserProfileFromEmail(EMAIL))
                .thenReturn(Optional.of(userProfile));

        when(authenticationService.getUserProfileFromEmail(TEST_CLIENT_EMAIL))
                .thenReturn(Optional.of(userProfile));

        when(configurationService.getDefaultOtpCodeExpiry()).thenReturn(CODE_EXPIRY_TIME);

        when(userProfile.getSubjectID()).thenReturn(TEST_SUBJECT_ID);

        when(configurationService.getEnvironment()).thenReturn("unit-test");
        when(configurationService.getCodeMaxRetries()).thenReturn(MAX_RETRIES);
        when(configurationService.getMaxEmailReAuthRetries()).thenReturn(MAX_RETRIES);
        when(configurationService.getMaxPasswordRetries()).thenReturn(MAX_RETRIES);
        when(authSessionService.getSessionFromRequestHeaders(any()))
                .thenReturn(Optional.of(authSession));
        when(userActionsManager.correctSmsOtpReceived(any(), any()))
                .thenReturn(Result.success(null));
        when(userActionsManager.correctEmailOtpReceived(any(), any()))
                .thenReturn(Result.success(null));
        when(userActionsManager.incorrectEmailOtpReceived(any(), any()))
                .thenReturn(Result.success(null));
        when(userActionsManager.incorrectSmsOtpReceived(any(), any()))
                .thenReturn(Result.success(null));
        when(permissionDecisionManager.canVerifyEmailOtp(any(), any()))
                .thenReturn(Result.success(new Decision.Permitted(0)));
        when(permissionDecisionManager.canVerifyMfaOtp(any(), any()))
                .thenReturn(Result.success(new Decision.Permitted(0)));
    }

    @Test
    void shouldReturn400IfRequestIsMissingNotificationType() {
        var body = format("{ \"code\": \"%s\"}", CODE);
        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, body);

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);
        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.REQUEST_MISSING_PARAMS));
        verifyNoInteractions(accountModifiersService);
    }

    @Test
    void shouldReturn400IfSessionIdIsInvalid() {
        String body =
                format("{ \"code\": \"%s\", \"notificationType\": \"%s\"  }", CODE, VERIFY_EMAIL);
        APIGatewayProxyResponseEvent result = makeCallWithCode(body, Optional.empty());

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.SESSION_ID_MISSING));
        verifyNoInteractions(accountModifiersService);
    }

    @Test
    void shouldReturn400IfNotificationTypeIsNotValid() {
        APIGatewayProxyResponseEvent result = makeCallWithCode(CODE, "VERIFY_TEXT");

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.REQUEST_MISSING_PARAMS));
        verifyNoInteractions(accountModifiersService);
    }

    private static Stream<NotificationType> emailNotificationTypes() {
        return Stream.of(VERIFY_EMAIL, VERIFY_CHANGE_HOW_GET_SECURITY_CODES);
    }

    @ParameterizedTest
    @MethodSource("emailNotificationTypes")
    void shouldReturn204ForValidEmailCodeRequest(NotificationType emailNotificationType) {
        when(codeStorageService.getOtpCode(EMAIL, emailNotificationType))
                .thenReturn(Optional.of(CODE));
        when(mfaMethodsService.getMfaMethods(EMAIL))
                .thenReturn(Result.failure(MfaRetrieveFailureReason.USER_DOES_NOT_HAVE_ACCOUNT));
        APIGatewayProxyResponseEvent result =
                makeCallWithCode(CODE, emailNotificationType.toString());

        assertThat(result, hasStatus(204));
        verify(codeStorageService).deleteOtpCode(EMAIL, emailNotificationType);
        verifyNoInteractions(accountModifiersService);
        verify(authSessionService).updateSession(any(AuthSessionItem.class));
        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.AUTH_CODE_VERIFIED,
                        AUDIT_CONTEXT,
                        pair("notification-type", emailNotificationType.name()),
                        pair(
                                "account-recovery",
                                emailNotificationType.equals(VERIFY_CHANGE_HOW_GET_SECURITY_CODES)),
                        pair(
                                "journey-type",
                                emailNotificationType.equals(VERIFY_CHANGE_HOW_GET_SECURITY_CODES)
                                        ? "ACCOUNT_RECOVERY"
                                        : "REGISTRATION"));
    }

    @ParameterizedTest
    @MethodSource("emailNotificationTypes")
    void checkAuditEventStillEmittedWhenTICFHeaderNotProvided(
            NotificationType emailNotificationType) {
        when(codeStorageService.getOtpCode(EMAIL, emailNotificationType))
                .thenReturn(Optional.of(CODE));
        when(mfaMethodsService.getMfaMethods(EMAIL))
                .thenReturn(Result.failure(MfaRetrieveFailureReason.USER_DOES_NOT_HAVE_ACCOUNT));

        String body =
                format(
                        "{ \"code\": \"%s\", \"notificationType\": \"%s\"  }",
                        CODE, emailNotificationType.toString());
        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS_WITHOUT_AUDIT_ENCODED, body);

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(204));
        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.AUTH_CODE_VERIFIED,
                        AUDIT_CONTEXT.withTxmaAuditEncoded(Optional.empty()),
                        pair("notification-type", emailNotificationType.name()),
                        pair(
                                "account-recovery",
                                emailNotificationType.equals(VERIFY_CHANGE_HOW_GET_SECURITY_CODES)),
                        pair(
                                "journey-type",
                                emailNotificationType.equals(VERIFY_CHANGE_HOW_GET_SECURITY_CODES)
                                        ? "ACCOUNT_RECOVERY"
                                        : "REGISTRATION"));
    }

    @ParameterizedTest
    @MethodSource("emailNotificationTypes")
    void shouldReturnEmailCodeNotValidStateIfRequestCodeDoesNotMatchStoredCode(
            NotificationType emailNotificationType) {
        when(codeStorageService.getOtpCode(EMAIL, emailNotificationType))
                .thenReturn(Optional.of(CODE));
        when(mfaMethodsService.getMfaMethods(EMAIL))
                .thenReturn(Result.failure(MfaRetrieveFailureReason.USER_DOES_NOT_HAVE_ACCOUNT));

        var expectedJourneyType =
                switch (emailNotificationType) {
                    case VERIFY_CHANGE_HOW_GET_SECURITY_CODES -> ACCOUNT_RECOVERY;
                    case VERIFY_EMAIL -> REGISTRATION;
                    default -> null;
                };

        if (expectedJourneyType == null) {
            fail("Internal test error, must have a journey type");
        }

        APIGatewayProxyResponseEvent result =
                makeCallWithCode(INVALID_CODE, emailNotificationType.toString());

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.INVALID_EMAIL_CODE_ENTERED));
        verifyNoInteractions(accountModifiersService);

        ArgumentCaptor<AuditService.MetadataPair[]> metadataCaptor =
                ArgumentCaptor.forClass(AuditService.MetadataPair[].class);

        verify(auditService)
                .submitAuditEvent(
                        eq(FrontendAuditableEvent.AUTH_INVALID_CODE_SENT),
                        eq(AUDIT_CONTEXT),
                        metadataCaptor.capture());

        List<AuditService.MetadataPair> expected =
                List.of(
                        pair("notification-type", emailNotificationType.name()),
                        pair(
                                "account-recovery",
                                emailNotificationType.equals(VERIFY_CHANGE_HOW_GET_SECURITY_CODES)),
                        pair("journey-type", expectedJourneyType.name()));

        List<AuditService.MetadataPair> actual = Arrays.asList(metadataCaptor.getValue());

        assertTrue(expected.containsAll(actual));
        assertTrue(actual.containsAll(expected));
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "testclient.user1@digital.cabinet-office.gov.uk",
                "abc@digital.cabinet-office.gov.uk",
                "abc.def@digital.cabinet-office.gov.uk",
                "testclient.user2@internet.com",
            })
    void shouldReturn204ForValidVerifyEmailRequestUsingTestClient(String email) {
        when(configurationService.isTestClientsEnabled()).thenReturn(true);
        when(testUserHelper.isTestJourney(any(UserContext.class))).thenReturn(true);
        when(configurationService.getTestClientVerifyEmailOTP())
                .thenReturn(Optional.of(TEST_CLIENT_CODE));
        when(codeStorageService.getOtpCode(email, VERIFY_EMAIL)).thenReturn(Optional.of(CODE));
        when(mfaMethodsService.getMfaMethods(email))
                .thenReturn(Result.failure(MfaRetrieveFailureReason.USER_DOES_NOT_HAVE_ACCOUNT));
        authSession.setEmailAddress(email);
        authSession.setClientId(TEST_CLIENT_ID);
        String body =
                format(
                        "{ \"code\": \"%s\", \"notificationType\": \"%s\"  }",
                        TEST_CLIENT_CODE, VERIFY_EMAIL);
        var result = makeCallWithCode(body, Optional.of(authSession));

        assertThat(result, hasStatus(204));
        verifyNoInteractions(accountModifiersService);
        verify(codeStorageService).deleteOtpCode(email, VERIFY_EMAIL);
        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.AUTH_CODE_VERIFIED,
                        AUDIT_CONTEXT_FOR_TEST_CLIENT.withEmail(email),
                        pair("notification-type", VERIFY_EMAIL.name()),
                        pair("account-recovery", false),
                        pair("journey-type", "REGISTRATION"));
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "testclient.user1@digital1.cabinet-office.gov.uk",
                "abc@digital1.cabinet-office.gov.uk",
                "abc.def@digital1.cabinet-office.gov.uk",
                "testclient.user3@internet.com",
            })
    void
            shouldReturn200AndUseDefaultCodeForVerifyEmailRequestUsingTestClientWhenEmailDoesNotMatchAllowlist(
                    String email) {
        when(configurationService.isTestClientsEnabled()).thenReturn(true);
        when(configurationService.getTestClientVerifyEmailOTP())
                .thenReturn(Optional.of(TEST_CLIENT_CODE));
        when(codeStorageService.getOtpCode(email, VERIFY_EMAIL)).thenReturn(Optional.of(CODE));
        when(mfaMethodsService.getMfaMethods(email))
                .thenReturn(Result.failure(MfaRetrieveFailureReason.USER_DOES_NOT_HAVE_ACCOUNT));
        authSession.setEmailAddress(email);
        authSession.setClientId(TEST_CLIENT_ID);
        String body =
                format("{ \"code\": \"%s\", \"notificationType\": \"%s\"  }", CODE, VERIFY_EMAIL);
        var result = makeCallWithCode(body, Optional.of(authSession));

        assertThat(result, hasStatus(204));
        verifyNoInteractions(accountModifiersService);
        verify(codeStorageService).deleteOtpCode(email, VERIFY_EMAIL);
        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.AUTH_CODE_VERIFIED,
                        AUDIT_CONTEXT_FOR_TEST_CLIENT.withEmail(email),
                        pair("notification-type", VERIFY_EMAIL.name()),
                        pair("account-recovery", false),
                        pair("journey-type", "REGISTRATION"));
    }

    @Test
    void shouldReturnMaxReachedAndSetBlockWhenRegistrationEmailCodeAttemptsExceedMaxRetryCount() {
        when(codeStorageService.getOtpCode(EMAIL, VERIFY_EMAIL)).thenReturn(Optional.of(CODE));
        when(mfaMethodsService.getMfaMethods(EMAIL))
                .thenReturn(Result.failure(MfaRetrieveFailureReason.USER_DOES_NOT_HAVE_ACCOUNT));
        when(permissionDecisionManager.canVerifyEmailOtp(any(), any()))
                .thenReturn(Result.success(new Decision.Permitted(0)))
                .thenReturn(
                        Result.success(
                                new Decision.TemporarilyLockedOut(
                                        null, MAX_RETRIES, Instant.now(), false)));

        var result = makeCallWithCode(INVALID_CODE, VERIFY_EMAIL.name());

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.TOO_MANY_EMAIL_CODES_ENTERED));
        verifyNoInteractions(accountModifiersService);
        verify(userActionsManager).incorrectEmailOtpReceived(eq(JourneyType.REGISTRATION), any());
        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.AUTH_CODE_MAX_RETRIES_REACHED,
                        AUDIT_CONTEXT,
                        pair("notification-type", VERIFY_EMAIL.name()),
                        pair("account-recovery", false),
                        pair("journey-type", "REGISTRATION"));
    }

    @Test
    void shouldReturnMaxReachedAndNotSetBlockWhenAccountRecoveryEmailCodeIsBlocked() {
        when(permissionDecisionManager.canVerifyEmailOtp(
                        eq(JourneyType.ACCOUNT_RECOVERY), any(PermissionContext.class)))
                .thenReturn(
                        Result.success(
                                new Decision.TemporarilyLockedOut(
                                        null, MAX_RETRIES, Instant.now(), false)));

        var result = makeCallWithCode(CODE, VERIFY_CHANGE_HOW_GET_SECURITY_CODES.name());

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.TOO_MANY_EMAIL_CODES_FOR_MFA_RESET_ENTERED));
        verifyNoInteractions(accountModifiersService);
        verifyNoInteractions(auditService);
    }

    @Test
    void shouldReturnMaxReachedAndNotSetBlockWhenPasswordResetEmailCodeIsBlocked() {
        when(permissionDecisionManager.canVerifyEmailOtp(
                        eq(JourneyType.PASSWORD_RESET), any(PermissionContext.class)))
                .thenReturn(
                        Result.success(
                                new Decision.TemporarilyLockedOut(
                                        null, MAX_RETRIES, Instant.now(), false)));

        var result = makeCallWithCode(CODE, RESET_PASSWORD_WITH_CODE.name());

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.TOO_MANY_INVALID_PW_RESET_CODES_ENTERED));
        verifyNoInteractions(accountModifiersService);
        verifyNoInteractions(auditService);
    }

    @ParameterizedTest
    @MethodSource("codeRequestTypes")
    void shouldReturnMaxReachedAndNotSetBlockWhenSignInCodeIsBlocked(
            CodeRequestType codeRequestType, JourneyType journeyType) {
        when(permissionDecisionManager.canVerifyMfaOtp(any(), any(PermissionContext.class)))
                .thenReturn(
                        Result.success(
                                new Decision.TemporarilyLockedOut(
                                        null, MAX_RETRIES, Instant.now(), false)));

        var result = makeCallWithCode(CODE, MFA_SMS.name(), journeyType);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.TOO_MANY_INVALID_MFA_OTPS_ENTERED));
        verifyNoInteractions(accountModifiersService);
        verifyNoInteractions(auditService);
    }

    @Test
    void
            shouldReturnMaxReachedAndSetBlockWhenAccountRecoveryEmailCodeAttemptsExceedMaxRetryCount() {
        when(mfaMethodsService.getMfaMethods(EMAIL))
                .thenReturn(Result.failure(MfaRetrieveFailureReason.USER_DOES_NOT_HAVE_ACCOUNT));
        when(permissionDecisionManager.canVerifyEmailOtp(any(), any()))
                .thenReturn(Result.success(new Decision.Permitted(0)))
                .thenReturn(
                        Result.success(
                                new Decision.TemporarilyLockedOut(
                                        null, MAX_RETRIES, Instant.now(), false)));

        var result = makeCallWithCode(CODE, VERIFY_CHANGE_HOW_GET_SECURITY_CODES.name());

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.TOO_MANY_EMAIL_CODES_FOR_MFA_RESET_ENTERED));
        verify(userActionsManager)
                .incorrectEmailOtpReceived(eq(JourneyType.ACCOUNT_RECOVERY), any());
        verifyNoInteractions(accountModifiersService);
        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.AUTH_CODE_MAX_RETRIES_REACHED,
                        AUDIT_CONTEXT,
                        pair("notification-type", VERIFY_CHANGE_HOW_GET_SECURITY_CODES.name()),
                        pair("account-recovery", true),
                        pair("journey-type", "ACCOUNT_RECOVERY"));
    }

    @ParameterizedTest
    @MethodSource("codeRequestTypes")
    void shouldReturn204ForValidMfaSmsRequestAndRemoveAccountRecoveryBlockWhenPresent(
            CodeRequestType codeRequestType, JourneyType journeyType) {
        when(codeStorageService.getOtpCode(
                        EMAIL.concat(DEFAULT_SMS_METHOD.getDestination()), MFA_SMS))
                .thenReturn(Optional.of(CODE));
        when(mfaMethodsService.getMfaMethods(EMAIL))
                .thenReturn(Result.success(List.of(DEFAULT_SMS_METHOD)));
        when(permissionDecisionManager.canVerifyMfaOtp(any(), any()))
                .thenReturn(Result.success(new Decision.Permitted(MAX_RETRIES - 1)));
        when(accountModifiersService.isAccountRecoveryBlockPresent(anyString())).thenReturn(true);
        authSession.setIsNewAccount(AuthSessionItem.AccountState.EXISTING);

        when(configurationService.getInternalSectorUri()).thenReturn("http://" + SECTOR_HOST);
        when(authenticationService.getOrGenerateSalt(userProfile)).thenReturn(SALT);

        var result = makeCallWithCode(CODE, MFA_SMS.toString(), journeyType);

        assertThat(result, hasStatus(204));
        assertThat(authSession.getVerifiedMfaMethodType(), equalTo(MFAMethodType.SMS));
        verify(codeStorageService)
                .deleteOtpCode(EMAIL.concat(DEFAULT_SMS_METHOD.getDestination()), MFA_SMS);
        verify(accountModifiersService)
                .removeAccountRecoveryBlockIfPresent(INTERNAL_COMMON_SUBJECT_ID);
        verify(authSessionService, atLeastOnce())
                .updateSession(
                        argThat(
                                s ->
                                        s.getInternalCommonSubjectId()
                                                .equals(INTERNAL_COMMON_SUBJECT_ID)));
        verify(authSessionService, atLeastOnce())
                .updateSession(
                        argThat(s -> s.getAchievedCredentialStrength().equals(MEDIUM_LEVEL)));
        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.AUTH_CODE_VERIFIED,
                        AUDIT_CONTEXT.withMetadataItem(
                                pair(AUDIT_EVENT_EXTENSIONS_MFA_METHOD, "default")),
                        pair("notification-type", MFA_SMS.name()),
                        pair("account-recovery", false),
                        pair(
                                "journey-type",
                                journeyType != null ? String.valueOf(journeyType) : "SIGN_IN"),
                        pair("mfa-type", MFAMethodType.SMS.getValue()),
                        pair("loginFailureCount", MAX_RETRIES - 1),
                        pair("MFACodeEntered", "123456"));
        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.AUTH_ACCOUNT_RECOVERY_BLOCK_REMOVED,
                        AUDIT_CONTEXT.withMetadataItem(
                                pair(AUDIT_EVENT_EXTENSIONS_MFA_METHOD, "default")),
                        pair("mfa-type", MFAMethodType.SMS.getValue()));
        verify(cloudwatchMetricsService)
                .incrementAuthenticationSuccessWithMfa(
                        AuthSessionItem.AccountState.EXISTING,
                        CLIENT_ID,
                        CLIENT_NAME,
                        "P0",
                        false,
                        journeyType != null ? journeyType : JourneyType.SIGN_IN,
                        MFAMethodType.SMS,
                        PriorityIdentifier.DEFAULT);
    }

    @Test
    void shouldReturn204ForValidIdentifiedBackupSmsMfaMethod() {
        when(codeStorageService.getOtpCode(
                        EMAIL.concat(BACKUP_SMS_METHOD.getDestination()), MFA_SMS))
                .thenReturn(Optional.of(CODE));
        when(mfaMethodsService.getMfaMethods(EMAIL))
                .thenReturn(Result.success(List.of(DEFAULT_SMS_METHOD, BACKUP_SMS_METHOD)));
        when(permissionDecisionManager.canVerifyMfaOtp(any(), any()))
                .thenReturn(Result.success(new Decision.Permitted(MAX_RETRIES - 1)));
        when(accountModifiersService.isAccountRecoveryBlockPresent(anyString())).thenReturn(true);
        authSession.setIsNewAccount(AuthSessionItem.AccountState.EXISTING);

        when(configurationService.getInternalSectorUri()).thenReturn("http://" + SECTOR_HOST);
        when(authenticationService.getOrGenerateSalt(userProfile)).thenReturn(SALT);

        var result =
                makeCallWithCode(
                        CODE,
                        MFA_SMS.toString(),
                        JourneyType.SIGN_IN,
                        BACKUP_SMS_METHOD.getMfaIdentifier());

        assertThat(result, hasStatus(204));
        assertThat(authSession.getVerifiedMfaMethodType(), equalTo(MFAMethodType.SMS));
        verify(codeStorageService)
                .deleteOtpCode(EMAIL.concat(BACKUP_SMS_METHOD.getDestination()), MFA_SMS);
        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.AUTH_CODE_VERIFIED,
                        AUDIT_CONTEXT.withMetadataItem(
                                pair(AUDIT_EVENT_EXTENSIONS_MFA_METHOD, "backup")),
                        pair("notification-type", MFA_SMS.name()),
                        pair("account-recovery", false),
                        pair("journey-type", "SIGN_IN"),
                        pair("mfa-type", MFAMethodType.SMS.getValue()),
                        pair("loginFailureCount", MAX_RETRIES - 1),
                        pair("MFACodeEntered", "123456"));
    }

    @Test
    void shouldReturn204ForValidMfaSmsRequestAndNotRemoveAccountRecoveryBlockWhenNotPresent() {
        when(codeStorageService.getOtpCode(
                        EMAIL.concat(DEFAULT_SMS_METHOD.getDestination()), MFA_SMS))
                .thenReturn(Optional.of(CODE));
        when(permissionDecisionManager.canVerifyMfaOtp(any(), any()))
                .thenReturn(Result.success(new Decision.Permitted(MAX_RETRIES - 1)));
        when(accountModifiersService.isAccountRecoveryBlockPresent(INTERNAL_COMMON_SUBJECT_ID))
                .thenReturn(false);
        when(mfaMethodsService.getMfaMethods(EMAIL))
                .thenReturn(Result.success(List.of(DEFAULT_SMS_METHOD)));
        authSession.setIsNewAccount(AuthSessionItem.AccountState.EXISTING);

        var result = makeCallWithCode(CODE, MFA_SMS.toString());

        assertThat(result, hasStatus(204));
        assertThat(authSession.getVerifiedMfaMethodType(), equalTo(MFAMethodType.SMS));
        verify(codeStorageService)
                .deleteOtpCode(EMAIL.concat(DEFAULT_SMS_METHOD.getDestination()), MFA_SMS);
        verify(accountModifiersService, never()).removeAccountRecoveryBlockIfPresent(anyString());
        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.AUTH_CODE_VERIFIED,
                        AUDIT_CONTEXT.withMetadataItem(
                                pair(AUDIT_EVENT_EXTENSIONS_MFA_METHOD, "default")),
                        pair("notification-type", MFA_SMS.name()),
                        pair("account-recovery", false),
                        pair("journey-type", "SIGN_IN"),
                        pair("mfa-type", MFAMethodType.SMS.getValue()),
                        pair("loginFailureCount", MAX_RETRIES - 1),
                        pair("MFACodeEntered", "123456"));
        verify(cloudwatchMetricsService)
                .incrementAuthenticationSuccessWithMfa(
                        AuthSessionItem.AccountState.EXISTING,
                        CLIENT_ID,
                        CLIENT_NAME,
                        "P0",
                        false,
                        JourneyType.SIGN_IN,
                        MFAMethodType.SMS,
                        PriorityIdentifier.DEFAULT);
        assertThat(
                logging.events(),
                hasItem(
                        withMessageContaining(
                                "MFA code has been successfully verified for MFA type: SMS. JourneyType: SIGN_IN. CountryCode: 44")));
    }

    @Test
    void shouldUpdateAuthSessionMfaTypeAndAchievedCredentialStrength() {
        when(codeStorageService.getOtpCode(
                        EMAIL.concat(DEFAULT_SMS_METHOD.getDestination()), MFA_SMS))
                .thenReturn(Optional.of(CODE));
        when(mfaMethodsService.getMfaMethods(EMAIL))
                .thenReturn(Result.success(List.of(DEFAULT_SMS_METHOD)));
        when(accountModifiersService.isAccountRecoveryBlockPresent(INTERNAL_COMMON_SUBJECT_ID))
                .thenReturn(false);

        var result = makeCallWithCode(CODE, MFA_SMS.toString());

        assertThat(result, hasStatus(204));
        assertThat(authSession.getVerifiedMfaMethodType(), equalTo(MFAMethodType.SMS));
        verify(authSessionService, atLeastOnce())
                .updateSession(
                        argThat(
                                as ->
                                        as.getVerifiedMfaMethodType().equals(MFAMethodType.SMS)
                                                && as.getAchievedCredentialStrength()
                                                        .equals(MEDIUM_LEVEL)));
    }

    @Test
    void shouldReturnMfaCodeNotValidWhenCodeIsInvalid() {
        when(codeStorageService.getOtpCode(
                        EMAIL.concat(DEFAULT_SMS_METHOD.getDestination()), MFA_SMS))
                .thenReturn(Optional.of(CODE));
        when(mfaMethodsService.getMfaMethods(EMAIL))
                .thenReturn(Result.success(List.of(DEFAULT_SMS_METHOD)));
        when(permissionDecisionManager.canVerifyMfaOtp(any(), any()))
                .thenReturn(Result.success(new Decision.Permitted(0)))
                .thenReturn(Result.success(new Decision.Permitted(MAX_RETRIES - 1)));

        APIGatewayProxyResponseEvent result = makeCallWithCode(INVALID_CODE, MFA_SMS.toString());

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.INVALID_MFA_CODE_ENTERED));
        verifyNoInteractions(accountModifiersService);

        ArgumentCaptor<AuditService.MetadataPair[]> metadataCaptor =
                ArgumentCaptor.forClass(AuditService.MetadataPair[].class);

        verify(auditService)
                .submitAuditEvent(
                        eq(FrontendAuditableEvent.AUTH_INVALID_CODE_SENT),
                        eq(
                                AUDIT_CONTEXT.withMetadataItem(
                                        pair(AUDIT_EVENT_EXTENSIONS_MFA_METHOD, "default"))),
                        metadataCaptor.capture());

        List<AuditService.MetadataPair> expected =
                List.of(
                        pair("notification-type", MFA_SMS.name()),
                        pair("account-recovery", false),
                        pair("journey-type", SIGN_IN.name()),
                        pair("mfa-type", MFAMethodType.SMS.getValue()),
                        pair("loginFailureCount", MAX_RETRIES - 1),
                        pair("MFACodeEntered", "6543221"),
                        pair("MaxSmsCount", configurationService.getCodeMaxRetries()));

        List<AuditService.MetadataPair> actual = Arrays.asList(metadataCaptor.getValue());

        assertTrue(expected.containsAll(actual));
        assertTrue(actual.containsAll(expected));
    }

    @ParameterizedTest
    @MethodSource("codeRequestTypes")
    void shouldReturnMaxReachedAndSetBlockedMfaCodeAttemptsWhenSignInExceedMaxRetryCount(
            CodeRequestType codeRequestType, JourneyType journeyType) {
        when(codeStorageService.getOtpCode(
                        EMAIL.concat(DEFAULT_SMS_METHOD.getDestination()), MFA_SMS))
                .thenReturn(Optional.of(CODE));
        when(mfaMethodsService.getMfaMethods(EMAIL))
                .thenReturn(Result.success(List.of(DEFAULT_SMS_METHOD)));
        if (journeyType != REAUTHENTICATION) {
            when(permissionDecisionManager.canVerifyMfaOtp(any(), any()))
                    .thenReturn(Result.success(new Decision.Permitted(0)))
                    .thenReturn(
                            Result.success(
                                    new Decision.TemporarilyLockedOut(
                                            null, MAX_RETRIES, Instant.now(), false)));
        }

        var result = makeCallWithCode(INVALID_CODE, MFA_SMS.toString(), journeyType);

        assertThat(result, hasStatus(400));
        if (journeyType != REAUTHENTICATION) {
            assertThat(result, hasJsonBody(ErrorResponse.TOO_MANY_INVALID_MFA_OTPS_ENTERED));
        } else {
            assertThat(result, hasJsonBody(ErrorResponse.INVALID_MFA_CODE_ENTERED));
        }

        verify(userActionsManager).incorrectSmsOtpReceived(any(), any());

        verifyNoInteractions(accountModifiersService);

        if (journeyType != REAUTHENTICATION) {
            verify(auditService)
                    .submitAuditEvent(
                            FrontendAuditableEvent.AUTH_CODE_MAX_RETRIES_REACHED,
                            AUDIT_CONTEXT.withMetadataItem(
                                    pair(AUDIT_EVENT_EXTENSIONS_MFA_METHOD, "default")),
                            pair("notification-type", MFA_SMS.name()),
                            pair("account-recovery", false),
                            pair(
                                    "journey-type",
                                    journeyType != null ? String.valueOf(journeyType) : "SIGN_IN"),
                            pair("mfa-type", MFAMethodType.SMS.getValue()),
                            pair("loginFailureCount", 0),
                            pair("MFACodeEntered", INVALID_CODE),
                            pair("MaxSmsCount", configurationService.getCodeMaxRetries()));
        }
    }

    @Test
    void shouldReturnMaxReachedAndSetBlockedMfaCodeAttemptsWhenPasswordResetExceedMaxRetryCount() {
        when(codeStorageService.getOtpCode(EMAIL, RESET_PASSWORD_WITH_CODE))
                .thenReturn(Optional.of(CODE));
        when(mfaMethodsService.getMfaMethods(EMAIL))
                .thenReturn(Result.success(List.of(DEFAULT_SMS_METHOD)));
        when(permissionDecisionManager.canVerifyEmailOtp(any(), any()))
                .thenReturn(Result.success(new Decision.Permitted(0)))
                .thenReturn(
                        Result.success(
                                new Decision.TemporarilyLockedOut(
                                        null, MAX_RETRIES, Instant.now(), false)));

        var result = makeCallWithCode(INVALID_CODE, RESET_PASSWORD_WITH_CODE.toString());

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.TOO_MANY_INVALID_PW_RESET_CODES_ENTERED));
        verify(userActionsManager).incorrectEmailOtpReceived(eq(JourneyType.PASSWORD_RESET), any());
        verifyNoInteractions(accountModifiersService);
        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.AUTH_CODE_MAX_RETRIES_REACHED,
                        AUDIT_CONTEXT.withMetadataItem(
                                pair(AUDIT_EVENT_EXTENSIONS_MFA_METHOD, "default")),
                        pair("notification-type", RESET_PASSWORD_WITH_CODE.name()),
                        pair("account-recovery", false),
                        pair("journey-type", "PASSWORD_RESET"));
    }

    @Test
    void shouldReturn204ForValidResetPasswordRequestUsingTestClient() {
        when(configurationService.isTestClientsEnabled()).thenReturn(true);
        when(testUserHelper.isTestJourney(any(UserContext.class))).thenReturn(true);
        when(configurationService.getTestClientVerifyEmailOTP())
                .thenReturn(Optional.of(TEST_CLIENT_CODE));
        when(codeStorageService.getOtpCode(
                        TEST_CLIENT_EMAIL.concat(DEFAULT_SMS_METHOD.getDestination()),
                        RESET_PASSWORD_WITH_CODE))
                .thenReturn(Optional.of(CODE));
        when(mfaMethodsService.getMfaMethods(TEST_CLIENT_EMAIL))
                .thenReturn(Result.success(List.of(DEFAULT_SMS_METHOD)));

        authSession.setEmailAddress(TEST_CLIENT_EMAIL);
        authSession.setClientId(TEST_CLIENT_ID);
        String body =
                format(
                        "{ \"code\": \"%s\", \"notificationType\": \"%s\"  }",
                        TEST_CLIENT_CODE, RESET_PASSWORD_WITH_CODE);
        APIGatewayProxyResponseEvent result = makeCallWithCode(body, Optional.of(authSession));

        verifyNoInteractions(accountModifiersService);
        verify(codeStorageService).deleteOtpCode(TEST_CLIENT_EMAIL, RESET_PASSWORD_WITH_CODE);
        assertThat(result, hasStatus(204));
    }

    @Test
    void shouldIncrementEnterMFAAuthenticationAttemptCountOnFailedReauthenticationAttempt() {
        when(mfaMethodsService.getMfaMethods(EMAIL))
                .thenReturn(Result.success(List.of(DEFAULT_SMS_METHOD)));

        var result = makeCallWithCode(INVALID_CODE, MFA_SMS.name(), REAUTHENTICATION);

        verify(userActionsManager).incorrectSmsOtpReceived(eq(REAUTHENTICATION), any());
        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.INVALID_MFA_CODE_ENTERED));
    }

    private static Stream<Arguments> reauthCountTypesAndMetadata() {
        return Stream.of(
                Arguments.arguments(
                        ENTER_EMAIL,
                        MAX_RETRIES,
                        0,
                        0,
                        ReauthFailureReasons.INCORRECT_EMAIL.getValue()),
                Arguments.arguments(
                        ENTER_PASSWORD,
                        0,
                        MAX_RETRIES,
                        0,
                        ReauthFailureReasons.INCORRECT_PASSWORD.getValue()),
                Arguments.arguments(
                        ENTER_MFA_CODE,
                        0,
                        0,
                        MAX_RETRIES,
                        ReauthFailureReasons.INCORRECT_OTP.getValue()));
    }

    @ParameterizedTest
    @MethodSource("reauthCountTypesAndMetadata")
    void shouldReturnErrorIfUserHasTooManyReauthAttemptCountsOfAnyType(
            CountType countType,
            int expectedEmailAttemptCount,
            int expectedPasswordAttemptCount,
            int expectedOtpAttemptCount,
            String expectedFailureReason) {
        try (MockedStatic<ClientSubjectHelper> mockedClientSubjectHelperClass =
                Mockito.mockStatic(ClientSubjectHelper.class, Mockito.CALLS_REAL_METHODS)) {
            var detailedCounts = Map.of(countType, MAX_RETRIES);
            var forbiddenReason =
                    switch (countType) {
                        case ENTER_EMAIL -> ForbiddenReason
                                .EXCEEDED_INCORRECT_EMAIL_ADDRESS_SUBMISSION_LIMIT;
                        case ENTER_PASSWORD -> ForbiddenReason
                                .EXCEEDED_INCORRECT_PASSWORD_SUBMISSION_LIMIT;
                        case ENTER_MFA_CODE,
                                ENTER_AUTH_APP_CODE,
                                ENTER_SMS_CODE,
                                ENTER_EMAIL_CODE -> ForbiddenReason
                                .EXCEEDED_INCORRECT_MFA_OTP_SUBMISSION_LIMIT;
                    };
            when(permissionDecisionManager.canVerifyMfaOtp(eq(REAUTHENTICATION), any()))
                    .thenReturn(
                            Result.success(
                                    new Decision.ReauthLockedOut(
                                            forbiddenReason,
                                            MAX_RETRIES,
                                            Instant.now(),
                                            false,
                                            detailedCounts,
                                            List.of(countType))));
            when(configurationService.getInternalSectorUri())
                    .thenReturn("https://test.account.gov.uk");
            Subject subject = new Subject(TEST_SUBJECT_ID);
            mockedClientSubjectHelperClass
                    .when(
                            () ->
                                    ClientSubjectHelper.getSubject(
                                            eq(userProfile),
                                            any(AuthSessionItem.class),
                                            any(AuthenticationService.class)))
                    .thenReturn(subject);

            var result = makeCallWithCode(CODE, MFA_SMS.name(), REAUTHENTICATION);

            verify(auditService, times(1))
                    .submitAuditEvent(
                            FrontendAuditableEvent.AUTH_REAUTH_FAILED,
                            AUDIT_CONTEXT,
                            pair("rpPairwiseId", subject.getValue()),
                            pair("incorrect_email_attempt_count", expectedEmailAttemptCount),
                            pair("incorrect_password_attempt_count", expectedPasswordAttemptCount),
                            pair("incorrect_otp_code_attempt_count", expectedOtpAttemptCount),
                            pair("failure-reason", expectedFailureReason));
            verify(cloudwatchMetricsService)
                    .incrementCounter(
                            CloudwatchMetrics.REAUTH_FAILED.getValue(),
                            Map.of(
                                    ENVIRONMENT.getValue(),
                                    configurationService.getEnvironment(),
                                    FAILURE_REASON.getValue(),
                                    expectedFailureReason));

            assertThat(result, hasStatus(400));
            assertThat(result, hasJsonBody(ErrorResponse.TOO_MANY_INVALID_REAUTH_ATTEMPTS));
        }
    }

    private APIGatewayProxyResponseEvent makeCallWithCode(String code, String notificationType) {
        String body =
                format(
                        "{ \"code\": \"%s\", \"notificationType\": \"%s\"  }",
                        code, notificationType);
        return makeCallWithCode(body, Optional.of(authSession));
    }

    private APIGatewayProxyResponseEvent makeCallWithCode(
            String code, String notificationType, JourneyType journeyType) {
        if (journeyType == null) {
            return makeCallWithCode(code, notificationType);
        }
        String body =
                format(
                        "{ \"code\": \"%s\", \"notificationType\": \"%s\", \"journeyType\":\"%s\" }",
                        code, notificationType, journeyType.getValue());
        return makeCallWithCode(body, Optional.of(authSession));
    }

    private APIGatewayProxyResponseEvent makeCallWithCode(
            String code, String notificationType, JourneyType journeyType, String mfaMethodId) {
        if (mfaMethodId == null) {
            return makeCallWithCode(code, notificationType, journeyType);
        }
        String body =
                format(
                        "{ \"code\": \"%s\", \"notificationType\": \"%s\", \"journeyType\":\"%s\", \"mfaMethodId\":\"%s\" }",
                        code, notificationType, journeyType.getValue(), mfaMethodId);
        return makeCallWithCode(body, Optional.of(authSession));
    }

    private APIGatewayProxyResponseEvent makeCallWithCode(
            String body, Optional<AuthSessionItem> session) {
        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, body);

        when(authSessionService.getSessionFromRequestHeaders(event.getHeaders()))
                .thenReturn(session);

        return handler.handleRequest(event, context);
    }

    private static Stream<Arguments> codeRequestTypes() {
        return Stream.of(
                Arguments.of(CodeRequestType.MFA_PW_RESET_MFA, JourneyType.PASSWORD_RESET_MFA),
                Arguments.of(CodeRequestType.MFA_REAUTHENTICATION, REAUTHENTICATION),
                Arguments.of(CodeRequestType.MFA_SIGN_IN, JourneyType.SIGN_IN),
                Arguments.of(CodeRequestType.MFA_SIGN_IN, null));
    }

    @Test
    void shouldLogExceptionWhenGetRpPairwiseIdFails() {
        try (MockedStatic<ClientSubjectHelper> mockedClientSubjectHelperClass =
                Mockito.mockStatic(ClientSubjectHelper.class, Mockito.CALLS_REAL_METHODS)) {
            when(codeStorageService.getOtpCode(EMAIL, VERIFY_EMAIL)).thenReturn(Optional.of(CODE));
            when(mfaMethodsService.getMfaMethods(EMAIL))
                    .thenReturn(
                            Result.failure(MfaRetrieveFailureReason.USER_DOES_NOT_HAVE_ACCOUNT));
            mockedClientSubjectHelperClass
                    .when(
                            () ->
                                    ClientSubjectHelper.getSubject(
                                            eq(userProfile),
                                            any(AuthSessionItem.class),
                                            any(AuthenticationService.class)))
                    .thenThrow(new RuntimeException("Test exception"));

            var result = makeCallWithCode(CODE, VERIFY_EMAIL.toString());

            assertThat(result, hasStatus(204));
            assertThat(logging.events(), hasItem(withMessageContaining("Test exception")));
            assertThat(
                    logging.events(),
                    hasItem(
                            withMessageContaining(
                                    "Failed to derive Internal Common Subject Identifier. Defaulting to UNKNOWN.")));
        }
    }

    @Test
    void shouldCallCorrectSmsOtpReceivedWhenMfaSmsCodeIsValid() {
        // Arrange
        when(codeStorageService.getOtpCode(
                        EMAIL.concat(DEFAULT_SMS_METHOD.getDestination()), MFA_SMS))
                .thenReturn(Optional.of(CODE));
        when(mfaMethodsService.getMfaMethods(EMAIL))
                .thenReturn(Result.success(List.of(DEFAULT_SMS_METHOD)));
        when(userActionsManager.correctSmsOtpReceived(any(), any()))
                .thenReturn(Result.success(null));

        // Act
        var result = makeCallWithCode(CODE, MFA_SMS.toString());

        // Assert
        assertThat(result, hasStatus(204));
        verify(userActionsManager)
                .correctSmsOtpReceived(any(), argThat(pc -> pc.authSessionItem() != null));
    }

    @Test
    void shouldReturn500WhenCorrectSmsOtpReceivedReturnsInvalidUserContext() {
        // Arrange
        when(codeStorageService.getOtpCode(
                        EMAIL.concat(DEFAULT_SMS_METHOD.getDestination()), MFA_SMS))
                .thenReturn(Optional.of(CODE));
        when(mfaMethodsService.getMfaMethods(EMAIL))
                .thenReturn(Result.success(List.of(DEFAULT_SMS_METHOD)));
        when(userActionsManager.correctSmsOtpReceived(any(), any()))
                .thenReturn(Result.failure(TrackingError.INVALID_USER_CONTEXT));

        // Act
        var result = makeCallWithCode(CODE, MFA_SMS.toString());

        // Assert
        assertThat(result, hasStatus(500));
    }

    @Test
    void shouldReturn500WhenCorrectEmailOtpReceivedFails() {
        when(codeStorageService.getOtpCode(EMAIL, VERIFY_EMAIL)).thenReturn(Optional.of(CODE));
        when(mfaMethodsService.getMfaMethods(EMAIL))
                .thenReturn(Result.failure(MfaRetrieveFailureReason.USER_DOES_NOT_HAVE_ACCOUNT));
        when(userActionsManager.correctEmailOtpReceived(any(), any()))
                .thenReturn(Result.failure(TrackingError.INVALID_USER_CONTEXT));

        var result = makeCallWithCode(CODE, VERIFY_EMAIL.name());

        assertThat(result, hasStatus(500));
    }

    @Test
    void shouldReturn500WhenIncorrectSmsOtpReceivedFails() {
        when(codeStorageService.getOtpCode(
                        EMAIL.concat(DEFAULT_SMS_METHOD.getDestination()), MFA_SMS))
                .thenReturn(Optional.of(CODE));
        when(mfaMethodsService.getMfaMethods(EMAIL))
                .thenReturn(Result.success(List.of(DEFAULT_SMS_METHOD)));
        when(userActionsManager.incorrectSmsOtpReceived(any(), any()))
                .thenReturn(Result.failure(TrackingError.INVALID_USER_CONTEXT));

        var result = makeCallWithCode(INVALID_CODE, MFA_SMS.toString());

        assertThat(result, hasStatus(500));
    }

    @Test
    void shouldReturn500WhenIncorrectEmailOtpReceivedFails() {
        when(codeStorageService.getOtpCode(EMAIL, VERIFY_EMAIL)).thenReturn(Optional.of(CODE));
        when(mfaMethodsService.getMfaMethods(EMAIL))
                .thenReturn(Result.failure(MfaRetrieveFailureReason.USER_DOES_NOT_HAVE_ACCOUNT));
        when(userActionsManager.incorrectEmailOtpReceived(any(), any()))
                .thenReturn(Result.failure(TrackingError.INVALID_USER_CONTEXT));

        var result = makeCallWithCode(INVALID_CODE, VERIFY_EMAIL.name());

        assertThat(result, hasStatus(500));
    }

    @Test
    void shouldReturn500WhenCanVerifyEmailOtpReturnsFailure() {
        when(permissionDecisionManager.canVerifyEmailOtp(any(), any()))
                .thenReturn(Result.failure(DecisionError.STORAGE_SERVICE_ERROR));

        var result = makeCallWithCode(CODE, VERIFY_EMAIL.name());

        assertThat(result, hasStatus(500));
        assertThat(result, hasJsonBody(ErrorResponse.INTERNAL_SERVER_ERROR));
    }

    @Test
    void shouldReturn500WhenCanVerifyMfaOtpReturnsFailure() {
        when(mfaMethodsService.getMfaMethods(EMAIL))
                .thenReturn(Result.success(List.of(DEFAULT_SMS_METHOD)));
        when(permissionDecisionManager.canVerifyMfaOtp(any(), any()))
                .thenReturn(Result.failure(DecisionError.STORAGE_SERVICE_ERROR));

        var result = makeCallWithCode(CODE, MFA_SMS.name());

        assertThat(result, hasStatus(500));
        assertThat(result, hasJsonBody(ErrorResponse.INTERNAL_SERVER_ERROR));
    }

    @Nested
    class ForcedMfaResetRequestedAuditEventAndMetric {

        private static final MFAMethod INTERNATIONAL_SMS_METHOD =
                new MFAMethod(DEFAULT_SMS_METHOD).withDestination(INTERNATIONAL_MOBILE_NUMBER);

        @BeforeEach
        void setUp() {
            when(configurationService.isForcedMFAResetAfterMFACheckEnabled()).thenReturn(true);
            when(codeStorageService.getOtpCode(
                            EMAIL.concat(INTERNATIONAL_SMS_METHOD.getDestination()), MFA_SMS))
                    .thenReturn(Optional.of(CODE));
            when(mfaMethodsService.getMfaMethods(EMAIL))
                    .thenReturn(Result.success(List.of(INTERNATIONAL_SMS_METHOD)));
            authSession.setIsNewAccount(AuthSessionItem.AccountState.EXISTING);
        }

        @Test
        void shouldNotEmitMfaResetAuditEventOrMetricWhenFeatureFlagDisabled() {
            when(configurationService.isForcedMFAResetAfterMFACheckEnabled()).thenReturn(false);

            var result = makeCallWithCode(CODE, MFA_SMS.toString(), JourneyType.SIGN_IN);

            assertThat(result, hasStatus(204));
            verify(auditService, never())
                    .submitAuditEvent(
                            eq(FrontendAuditableEvent.AUTH_MFA_RESET_REQUESTED),
                            any(AuditContext.class),
                            any(AuditService.MetadataPair[].class));
            verify(cloudwatchMetricsService, never())
                    .incrementCounter(eq(FORCED_MFA_RESET_INITIATED.getValue()), any());
        }

        @Test
        void shouldNotEmitMfaResetAuditEventOrMetricForDomesticNumber() {
            when(codeStorageService.getOtpCode(
                            EMAIL.concat(DEFAULT_SMS_METHOD.getDestination()), MFA_SMS))
                    .thenReturn(Optional.of(CODE));
            when(mfaMethodsService.getMfaMethods(EMAIL))
                    .thenReturn(Result.success(List.of(DEFAULT_SMS_METHOD)));

            var result = makeCallWithCode(CODE, MFA_SMS.toString(), JourneyType.SIGN_IN);

            assertThat(result, hasStatus(204));
            verify(auditService, never())
                    .submitAuditEvent(
                            eq(FrontendAuditableEvent.AUTH_MFA_RESET_REQUESTED),
                            any(AuditContext.class),
                            any(AuditService.MetadataPair[].class));
            verify(cloudwatchMetricsService, never())
                    .incrementCounter(eq(FORCED_MFA_RESET_INITIATED.getValue()), any());
        }

        @Test
        void shouldNotEmitMfaResetAuditEventOrMetricForAccountRecoveryJourney() {
            var result = makeCallWithCode(CODE, MFA_SMS.toString(), JourneyType.ACCOUNT_RECOVERY);

            assertThat(result, hasStatus(204));
            verify(auditService, never())
                    .submitAuditEvent(
                            eq(FrontendAuditableEvent.AUTH_MFA_RESET_REQUESTED),
                            any(AuditContext.class),
                            any(AuditService.MetadataPair[].class));
            verify(cloudwatchMetricsService, never())
                    .incrementCounter(eq(FORCED_MFA_RESET_INITIATED.getValue()), any());
        }

        @ParameterizedTest
        @EnumSource(
                value = JourneyType.class,
                names = {"SIGN_IN", "REAUTHENTICATION", "PASSWORD_RESET_MFA"})
        void shouldEmitMfaResetAuditEventAndMetricForSmsUserWithInternationalNumber(
                JourneyType journeyType) {
            var result = makeCallWithCode(CODE, MFA_SMS.toString(), journeyType);

            assertThat(result, hasStatus(204));
            verify(auditService)
                    .submitAuditEvent(
                            eq(FrontendAuditableEvent.AUTH_MFA_RESET_REQUESTED),
                            eq(AUDIT_CONTEXT.withPhoneNumber(INTERNATIONAL_MOBILE_NUMBER)),
                            eq(pair(AUDIT_EVENT_EXTENSIONS_PHONE_NUMBER_COUNTRY_CODE, "7")),
                            eq(
                                    pair(
                                            AUDIT_EVENT_EXTENSIONS_MFA_RESET_TYPE,
                                            MfaResetType.FORCED_INTERNATIONAL_NUMBERS)),
                            eq(
                                    pair(
                                            AUDIT_EVENT_EXTENSIONS_JOURNEY_TYPE,
                                            JourneyType.ACCOUNT_RECOVERY)));
            verify(cloudwatchMetricsService)
                    .incrementCounter(
                            FORCED_MFA_RESET_INITIATED.getValue(),
                            Map.of(
                                    ENVIRONMENT.getValue(),
                                    configurationService.getEnvironment(),
                                    MFA_RESET_TYPE.getValue(),
                                    MfaResetType.FORCED_INTERNATIONAL_NUMBERS.toString()));
        }
    }
}
