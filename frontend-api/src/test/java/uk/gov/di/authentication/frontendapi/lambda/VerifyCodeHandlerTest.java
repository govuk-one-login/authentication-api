package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent;
import uk.gov.di.authentication.frontendapi.entity.ReauthFailureReasons;
import uk.gov.di.authentication.shared.domain.CloudwatchMetrics;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.CodeRequestType;
import uk.gov.di.authentication.shared.entity.CountType;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.NotificationType;
import uk.gov.di.authentication.shared.entity.PriorityIdentifier;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.helpers.SaltHelper;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthSessionService;
import uk.gov.di.authentication.shared.services.AuthenticationAttemptsService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoAccountModifiersService;
import uk.gov.di.authentication.shared.services.mfa.MFAMethodsService;
import uk.gov.di.authentication.shared.services.mfa.MfaRetrieveFailureReason;
import uk.gov.di.authentication.sharedtest.logging.CaptureLoggingExtension;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Objects;
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
import static uk.gov.di.authentication.shared.domain.AuditableEvent.AUDIT_EVENT_EXTENSIONS_MFA_METHOD;
import static uk.gov.di.authentication.shared.domain.CloudwatchMetricDimensions.ENVIRONMENT;
import static uk.gov.di.authentication.shared.domain.CloudwatchMetricDimensions.FAILURE_REASON;
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
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.BACKUP_SMS_METHOD;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.CLIENT_SESSION_ID;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.DEFAULT_SMS_METHOD;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.DI_PERSISTENT_SESSION_ID;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.EMAIL;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.ENCODED_DEVICE_DETAILS;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.INTERNAL_COMMON_SUBJECT_ID;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.IP_ADDRESS;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.SESSION_ID;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.VALID_HEADERS;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.VALID_HEADERS_WITHOUT_AUDIT_ENCODED;
import static uk.gov.di.authentication.shared.services.AuditService.MetadataPair.pair;
import static uk.gov.di.authentication.shared.services.CodeStorageService.CODE_BLOCKED_KEY_PREFIX;
import static uk.gov.di.authentication.shared.services.CodeStorageService.CODE_REQUEST_BLOCKED_KEY_PREFIX;
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
    private static final long LOCKOUT_DURATION = 799;
    private static final int MAX_RETRIES = 6;
    private final Context context = mock(Context.class);
    private final CodeStorageService codeStorageService = mock(CodeStorageService.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final UserProfile userProfile = mock(UserProfile.class);
    private final String expectedPairwiseId =
            ClientSubjectHelper.calculatePairwiseIdentifier(
                    TEST_SUBJECT_ID, CLIENT_SECTOR_HOST, SALT);
    private final AuthSessionItem authSession =
            new AuthSessionItem()
                    .withSessionId(SESSION_ID)
                    .withEmailAddress(EMAIL)
                    .withInternalCommonSubjectId(INTERNAL_COMMON_SUBJECT_ID)
                    .withClientId(CLIENT_ID)
                    .withClientName(CLIENT_NAME)
                    .withRpSectorIdentifierHost(CLIENT_SECTOR_HOST);
    private final ClientService clientService = mock(ClientService.class);
    private final AuthenticationService authenticationService = mock(AuthenticationService.class);
    private final AuditService auditService = mock(AuditService.class);
    private final CloudwatchMetricsService cloudwatchMetricsService =
            mock(CloudwatchMetricsService.class);
    private final DynamoAccountModifiersService accountModifiersService =
            mock(DynamoAccountModifiersService.class);
    private final AuthenticationAttemptsService authenticationAttemptsService =
            mock(AuthenticationAttemptsService.class);
    private final AuthSessionService authSessionService = mock(AuthSessionService.class);
    private final MFAMethodsService mfaMethodsService = mock(MFAMethodsService.class);

    private final ClientRegistry clientRegistry =
            new ClientRegistry()
                    .withTestClient(false)
                    .withClientID(CLIENT_ID)
                    .withClientName(CLIENT_NAME)
                    .withSectorIdentifierUri("https://" + CLIENT_SECTOR_HOST);
    private final ClientRegistry testClientRegistry =
            new ClientRegistry()
                    .withTestClient(true)
                    .withClientID(TEST_CLIENT_ID)
                    .withTestClientEmailAllowlist(
                            List.of(
                                    "testclient.user1@digital.cabinet-office.gov.uk",
                                    "^(.+)@digital.cabinet-office.gov.uk$",
                                    "testclient.user2@internet.com"));

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
                        clientService,
                        authenticationService,
                        codeStorageService,
                        auditService,
                        cloudwatchMetricsService,
                        accountModifiersService,
                        authenticationAttemptsService,
                        authSessionService,
                        mfaMethodsService);

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
        verifyNoInteractions(authenticationAttemptsService);
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
        when(clientService.getClient(CLIENT_ID)).thenReturn(Optional.of(clientRegistry));

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
        verifyNoInteractions(authenticationAttemptsService);
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
                        any(AuditContext.class),
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

        verifyNoInteractions(authenticationAttemptsService);
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
        verifyNoInteractions(authenticationAttemptsService);
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
        verifyNoInteractions(authenticationAttemptsService);
    }

    @Test
    void
            shouldReturnMaxReachedAndNotSetBlockWhenRegistrationEmailCodeAttemptsExceedMaxRetryCount() {
        when(codeStorageService.getIncorrectMfaCodeAttemptsCount(EMAIL))
                .thenReturn(MAX_RETRIES + 1);
        when(codeStorageService.getOtpCode(EMAIL, VERIFY_EMAIL)).thenReturn(Optional.of(CODE));
        when(mfaMethodsService.getMfaMethods(EMAIL))
                .thenReturn(Result.failure(MfaRetrieveFailureReason.USER_DOES_NOT_HAVE_ACCOUNT));
        var result = makeCallWithCode(INVALID_CODE, VERIFY_EMAIL.name());

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.TOO_MANY_EMAIL_CODES_ENTERED));
        verifyNoInteractions(accountModifiersService);
        verify(codeStorageService).deleteIncorrectMfaCodeAttemptsCount(EMAIL);
        verify(codeStorageService, never())
                .saveBlockedForEmail(EMAIL, CODE_BLOCKED_KEY_PREFIX, LOCKOUT_DURATION);
        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.AUTH_CODE_MAX_RETRIES_REACHED,
                        AUDIT_CONTEXT,
                        pair("notification-type", VERIFY_EMAIL.name()),
                        pair("account-recovery", false),
                        pair("journey-type", "REGISTRATION"));
        verifyNoInteractions(authenticationAttemptsService);
    }

    @Test
    void shouldReturnMaxReachedAndNotSetBlockWhenAccountRecoveryEmailCodeIsBlocked() {
        var codeBlockedKeyPrefix = CODE_BLOCKED_KEY_PREFIX + CodeRequestType.EMAIL_ACCOUNT_RECOVERY;
        when(codeStorageService.isBlockedForEmail(EMAIL, codeBlockedKeyPrefix)).thenReturn(true);

        var result = makeCallWithCode(CODE, VERIFY_CHANGE_HOW_GET_SECURITY_CODES.name());

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.TOO_MANY_EMAIL_CODES_FOR_MFA_RESET_ENTERED));
        verifyNoInteractions(accountModifiersService);
        verifyNoInteractions(auditService);
        verifyNoInteractions(authenticationAttemptsService);
    }

    @Test
    void shouldReturnMaxReachedAndNotSetBlockWhenPasswordResetEmailCodeIsBlocked() {
        var codeBlockedKeyPrefix = CODE_BLOCKED_KEY_PREFIX + CodeRequestType.EMAIL_PASSWORD_RESET;
        when(codeStorageService.isBlockedForEmail(EMAIL, codeBlockedKeyPrefix)).thenReturn(true);

        var result = makeCallWithCode(CODE, RESET_PASSWORD_WITH_CODE.name());

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.TOO_MANY_INVALID_PW_RESET_CODES_ENTERED));
        verifyNoInteractions(accountModifiersService);
        verifyNoInteractions(auditService);
        verifyNoInteractions(authenticationAttemptsService);
    }

    @ParameterizedTest
    @MethodSource("codeRequestTypes")
    void shouldReturnMaxReachedAndNotSetBlockWhenSignInCodeIsBlocked(
            CodeRequestType codeRequestType, JourneyType journeyType) {
        var codeBlockedKeyPrefix = CODE_BLOCKED_KEY_PREFIX + codeRequestType;
        when(codeStorageService.isBlockedForEmail(EMAIL, codeBlockedKeyPrefix)).thenReturn(true);

        var result = makeCallWithCode(CODE, MFA_SMS.name(), journeyType);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.TOO_MANY_INVALID_MFA_OTPS_ENTERED));
        verifyNoInteractions(accountModifiersService);
        verifyNoInteractions(auditService);
        verifyNoInteractions(authenticationAttemptsService);
    }

    // TODO remove temporary ZDD measure to reference existing deprecated keys when expired
    @Test
    void shouldReturnMaxReachedAndNotSetBlockWhenSignInCodeIsBlockedUsingDeprecatedKey() {
        JourneyType journeyType = JourneyType.SIGN_IN;

        var codeBlockedKeyPrefix =
                CODE_BLOCKED_KEY_PREFIX
                        + CodeRequestType.getDeprecatedCodeRequestTypeString(
                                MFAMethodType.SMS, journeyType);
        when(codeStorageService.isBlockedForEmail(EMAIL, codeBlockedKeyPrefix)).thenReturn(true);

        var result = makeCallWithCode(CODE, MFA_SMS.name(), journeyType);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.TOO_MANY_INVALID_MFA_OTPS_ENTERED));
        verifyNoInteractions(accountModifiersService);
        verifyNoInteractions(auditService);
        verifyNoInteractions(authenticationAttemptsService);
    }

    @Test
    void
            shouldReturnMaxReachedAndSetBlockWhenAccountRecoveryEmailCodeAttemptsExceedMaxRetryCount() {
        when(configurationService.getLockoutDuration()).thenReturn(LOCKOUT_DURATION);
        when(mfaMethodsService.getMfaMethods(EMAIL))
                .thenReturn(Result.failure(MfaRetrieveFailureReason.USER_DOES_NOT_HAVE_ACCOUNT));

        var codeBlockedKeyPrefix = CODE_BLOCKED_KEY_PREFIX + CodeRequestType.EMAIL_ACCOUNT_RECOVERY;
        when(codeStorageService.isBlockedForEmail(EMAIL, codeBlockedKeyPrefix)).thenReturn(false);
        when(codeStorageService.getIncorrectMfaCodeAttemptsCount(EMAIL))
                .thenReturn(MAX_RETRIES + 1);

        var result = makeCallWithCode(CODE, VERIFY_CHANGE_HOW_GET_SECURITY_CODES.name());

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.TOO_MANY_EMAIL_CODES_FOR_MFA_RESET_ENTERED));
        verify(codeStorageService)
                .saveBlockedForEmail(EMAIL, codeBlockedKeyPrefix, LOCKOUT_DURATION);
        verify(codeStorageService).deleteIncorrectMfaCodeAttemptsCount(EMAIL);
        verifyNoInteractions(accountModifiersService);
        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.AUTH_CODE_MAX_RETRIES_REACHED,
                        AUDIT_CONTEXT,
                        pair("notification-type", VERIFY_CHANGE_HOW_GET_SECURITY_CODES.name()),
                        pair("account-recovery", true),
                        pair("journey-type", "ACCOUNT_RECOVERY"));
        verifyNoInteractions(authenticationAttemptsService);
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
        when(codeStorageService.getIncorrectMfaCodeAttemptsCount(EMAIL))
                .thenReturn(MAX_RETRIES - 1);
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
        verifyNoInteractions(authenticationAttemptsService);
    }

    @Test
    void shouldReturn204ForValidIdentifiedBackupSmsMfaMethod() {
        when(codeStorageService.getOtpCode(
                        EMAIL.concat(BACKUP_SMS_METHOD.getDestination()), MFA_SMS))
                .thenReturn(Optional.of(CODE));
        when(mfaMethodsService.getMfaMethods(EMAIL))
                .thenReturn(Result.success(List.of(DEFAULT_SMS_METHOD, BACKUP_SMS_METHOD)));
        when(codeStorageService.getIncorrectMfaCodeAttemptsCount(EMAIL))
                .thenReturn(MAX_RETRIES - 1);
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
        verifyNoInteractions(authenticationAttemptsService);
    }

    @Test
    void shouldReturn204ForValidMfaSmsRequestAndNotRemoveAccountRecoveryBlockWhenNotPresent() {
        when(codeStorageService.getOtpCode(
                        EMAIL.concat(DEFAULT_SMS_METHOD.getDestination()), MFA_SMS))
                .thenReturn(Optional.of(CODE));
        when(codeStorageService.getIncorrectMfaCodeAttemptsCount(EMAIL))
                .thenReturn(MAX_RETRIES - 1);
        when(accountModifiersService.isAccountRecoveryBlockPresent(INTERNAL_COMMON_SUBJECT_ID))
                .thenReturn(false);
        when(mfaMethodsService.getMfaMethods(EMAIL))
                .thenReturn(Result.success(List.of(DEFAULT_SMS_METHOD)));
        withReauthTurnedOn();
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
    }

    @Test
    void shouldUpdateAuthSessionMfaTypeAndAchievedCredentialStrength() {
        when(codeStorageService.getOtpCode(
                        EMAIL.concat(DEFAULT_SMS_METHOD.getDestination()), MFA_SMS))
                .thenReturn(Optional.of(CODE));
        when(mfaMethodsService.getMfaMethods(EMAIL))
                .thenReturn(Result.success(List.of(DEFAULT_SMS_METHOD)));
        when(codeStorageService.getIncorrectMfaCodeAttemptsCount(EMAIL))
                .thenReturn(MAX_RETRIES - 1);
        when(accountModifiersService.isAccountRecoveryBlockPresent(INTERNAL_COMMON_SUBJECT_ID))
                .thenReturn(false);
        withReauthTurnedOn();

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
        when(codeStorageService.getIncorrectMfaCodeAttemptsCount(EMAIL))
                .thenReturn(MAX_RETRIES - 1);

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
        withReauthTurnedOn();
        when(configurationService.getLockoutDuration()).thenReturn(LOCKOUT_DURATION);
        when(codeStorageService.getOtpCode(
                        EMAIL.concat(DEFAULT_SMS_METHOD.getDestination()), MFA_SMS))
                .thenReturn(Optional.of(CODE));
        when(mfaMethodsService.getMfaMethods(EMAIL))
                .thenReturn(Result.success(List.of(DEFAULT_SMS_METHOD)));
        when(codeStorageService.getIncorrectMfaCodeAttemptsCount(EMAIL))
                .thenReturn(MAX_RETRIES + 1);

        var result = makeCallWithCode(INVALID_CODE, MFA_SMS.toString(), journeyType);

        assertThat(result, hasStatus(400));
        if (journeyType != REAUTHENTICATION) {
            assertThat(result, hasJsonBody(ErrorResponse.TOO_MANY_INVALID_MFA_OTPS_ENTERED));
        } else {
            assertThat(result, hasJsonBody(ErrorResponse.INVALID_MFA_CODE_ENTERED));
        }

        if (codeRequestType != CodeRequestType.MFA_REAUTHENTICATION) {
            verify(codeStorageService)
                    .saveBlockedForEmail(
                            EMAIL, CODE_BLOCKED_KEY_PREFIX + codeRequestType, LOCKOUT_DURATION);
        }

        verifyNoInteractions(accountModifiersService);

        if (journeyType != REAUTHENTICATION) {
            verify(codeStorageService).deleteIncorrectMfaCodeAttemptsCount(EMAIL);
            verify(auditService)
                    .submitAuditEvent(
                            FrontendAuditableEvent.AUTH_CODE_MAX_RETRIES_REACHED,
                            AUDIT_CONTEXT.withMetadataItem(pair("mfa-method", "default")),
                            pair("notification-type", MFA_SMS.name()),
                            pair("account-recovery", false),
                            pair(
                                    "journey-type",
                                    journeyType != null ? String.valueOf(journeyType) : "SIGN_IN"),
                            pair("mfa-type", MFAMethodType.SMS.getValue()),
                            pair("loginFailureCount", MAX_RETRIES + 1),
                            pair("MFACodeEntered", "6543221"),
                            pair("MaxSmsCount", configurationService.getCodeMaxRetries()));
        }
    }

    @Test
    void shouldReturnMaxReachedAndSetBlockedMfaCodeAttemptsWhenPasswordResetExceedMaxRetryCount() {
        when(configurationService.getLockoutDuration()).thenReturn(LOCKOUT_DURATION);
        when(codeStorageService.getOtpCode(EMAIL, RESET_PASSWORD_WITH_CODE))
                .thenReturn(Optional.of(CODE));
        when(mfaMethodsService.getMfaMethods(EMAIL))
                .thenReturn(Result.success(List.of(DEFAULT_SMS_METHOD)));
        when(codeStorageService.getIncorrectMfaCodeAttemptsCount(EMAIL))
                .thenReturn(MAX_RETRIES + 1);

        var result = makeCallWithCode(INVALID_CODE, RESET_PASSWORD_WITH_CODE.toString());

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.TOO_MANY_INVALID_PW_RESET_CODES_ENTERED));
        verify(codeStorageService)
                .saveBlockedForEmail(
                        EMAIL,
                        CODE_BLOCKED_KEY_PREFIX + CodeRequestType.EMAIL_PASSWORD_RESET,
                        LOCKOUT_DURATION);
        verifyNoInteractions(accountModifiersService);
        verify(codeStorageService).deleteIncorrectMfaCodeAttemptsCount(EMAIL);
        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.AUTH_CODE_MAX_RETRIES_REACHED,
                        AUDIT_CONTEXT.withMetadataItem(pair("mfa-method", "default")),
                        pair("notification-type", RESET_PASSWORD_WITH_CODE.name()),
                        pair("account-recovery", false),
                        pair("journey-type", "PASSWORD_RESET"));
    }

    @Test
    void shouldReturn204ForValidResetPasswordRequestUsingTestClient() {
        when(configurationService.isTestClientsEnabled()).thenReturn(true);
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

    private static Stream<Arguments> expectedMfaCodeBlocks() {
        return Stream.of(
                Arguments.of(
                        CODE_BLOCKED_KEY_PREFIX + CodeRequestType.MFA_PW_RESET_MFA,
                        ErrorResponse.TOO_MANY_INVALID_MFA_OTPS_ENTERED),
                Arguments.of(
                        CODE_BLOCKED_KEY_PREFIX + "PW_RESET_MFA_" + MFAMethodType.SMS,
                        ErrorResponse.TOO_MANY_INVALID_MFA_OTPS_ENTERED),
                Arguments.of(
                        CODE_REQUEST_BLOCKED_KEY_PREFIX + CodeRequestType.MFA_PW_RESET_MFA,
                        ErrorResponse.BLOCKED_FOR_SENDING_MFA_OTPS),
                Arguments.of(
                        CODE_REQUEST_BLOCKED_KEY_PREFIX + "PW_RESET_MFA_" + MFAMethodType.SMS,
                        ErrorResponse.BLOCKED_FOR_SENDING_MFA_OTPS));
    }

    @ParameterizedTest
    @MethodSource("expectedMfaCodeBlocks")
    void shouldReturn400ForValidResetPasswordRequestWhenUserHasAnMFACodeBlock(
            String blockKeyPrefix, ErrorResponse expectedError) {
        when(configurationService.isTestClientsEnabled()).thenReturn(true);
        when(configurationService.getTestClientVerifyEmailOTP())
                .thenReturn(Optional.of(TEST_CLIENT_CODE));
        when(codeStorageService.getOtpCode(
                        TEST_CLIENT_EMAIL.concat(DEFAULT_SMS_METHOD.getDestination()),
                        RESET_PASSWORD_WITH_CODE))
                .thenReturn(Optional.of(CODE));
        when(mfaMethodsService.getMfaMethods(TEST_CLIENT_EMAIL))
                .thenReturn(Result.success(List.of(DEFAULT_SMS_METHOD)));
        when(codeStorageService.isBlockedForEmail(TEST_CLIENT_EMAIL, blockKeyPrefix))
                .thenReturn(true);

        authSession.setEmailAddress(TEST_CLIENT_EMAIL);
        authSession.setClientId(TEST_CLIENT_ID);
        String body =
                format(
                        "{ \"code\": \"%s\", \"notificationType\": \"%s\"  }",
                        TEST_CLIENT_CODE, RESET_PASSWORD_WITH_CODE);
        APIGatewayProxyResponseEvent result = makeCallWithCode(body, Optional.of(authSession));

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(expectedError));
    }

    @Test
    void shouldNotCheckForMFACodeBlocksOnANonePasswordResetJourney() {
        when(configurationService.isTestClientsEnabled()).thenReturn(true);
        when(configurationService.getTestClientVerifyEmailOTP())
                .thenReturn(Optional.of(TEST_CLIENT_CODE));
        when(codeStorageService.getOtpCode(
                        TEST_CLIENT_EMAIL.concat(DEFAULT_SMS_METHOD.getDestination()), MFA_SMS))
                .thenReturn(Optional.of(CODE));
        when(mfaMethodsService.getMfaMethods(TEST_CLIENT_EMAIL))
                .thenReturn(Result.success(List.of(DEFAULT_SMS_METHOD)));

        authSession.setEmailAddress(TEST_CLIENT_EMAIL);
        authSession.setClientId(TEST_CLIENT_ID);
        String body =
                format(
                        "{ \"code\": \"%s\", \"notificationType\": \"%s\"  }",
                        TEST_CLIENT_CODE, SIGN_IN);
        makeCallWithCode(body, Optional.of(authSession));

        verify(codeStorageService, never())
                .isBlockedForEmail(
                        TEST_CLIENT_EMAIL,
                        CODE_REQUEST_BLOCKED_KEY_PREFIX + CodeRequestType.MFA_PW_RESET_MFA);
    }

    @ParameterizedTest
    @MethodSource("codeRequestTypes")
    void shouldDeleteCountOnSuccessfulSMSCodeRequest(
            CodeRequestType codeRequestType, JourneyType journeyType) {
        when(codeStorageService.getOtpCode(
                        EMAIL.concat(DEFAULT_SMS_METHOD.getDestination()), MFA_SMS))
                .thenReturn(Optional.of(CODE));
        when(mfaMethodsService.getMfaMethods(EMAIL))
                .thenReturn(Result.success(List.of(DEFAULT_SMS_METHOD)));
        withReauthTurnedOn();
        var existingCounts = Map.of(ENTER_EMAIL, 5, ENTER_PASSWORD, 1);
        when(authenticationAttemptsService.getCountsByJourneyForSubjectIdAndRpPairwiseId(
                        any(), any(), eq(REAUTHENTICATION)))
                .thenReturn(existingCounts);
        when(configurationService.getInternalSectorUri()).thenReturn("http://" + SECTOR_HOST);
        when(authenticationService.getOrGenerateSalt(userProfile)).thenReturn(SALT);
        var result = makeCallWithCode(CODE, MFA_SMS.toString(), journeyType);

        List.of(TEST_SUBJECT_ID, expectedPairwiseId)
                .forEach(
                        identifier ->
                                verify(
                                                authenticationAttemptsService,
                                                times(CountType.values().length))
                                        .deleteCount(
                                                eq(identifier),
                                                eq(JourneyType.REAUTHENTICATION),
                                                any()));

        if (journeyType == REAUTHENTICATION) {
            verify(authSessionService, atLeastOnce())
                    .updateSession(
                            argThat(
                                    s ->
                                            s.getPreservedReauthCountsForAuditMap()
                                                    .equals(existingCounts)));
        } else {
            verify(authSessionService, never())
                    .updateSession(
                            argThat(
                                    s ->
                                            Objects.equals(
                                                    s.getPreservedReauthCountsForAuditMap(),
                                                    existingCounts)));
        }

        assertThat(result, hasStatus(204));
    }

    @Test
    void shouldIncrementEnterMFAAuthenticationAttemptCountOnFailedReauthenticationAttempt() {
        long ttl = 120L;
        withReauthTurnedOn();
        when(mfaMethodsService.getMfaMethods(EMAIL))
                .thenReturn(Result.success(List.of(DEFAULT_SMS_METHOD)));
        when(configurationService.getReauthEnterSMSCodeCountTTL()).thenReturn(ttl);
        MockedStatic<NowHelper> mockedNowHelperClass = Mockito.mockStatic(NowHelper.class);
        mockedNowHelperClass
                .when(() -> NowHelper.nowPlus(ttl, ChronoUnit.SECONDS))
                .thenReturn(Date.from(Instant.parse("2099-01-01T00:00:00.00Z")));

        var result = makeCallWithCode(INVALID_CODE, MFA_SMS.name(), REAUTHENTICATION);

        verify(authenticationAttemptsService, times(1))
                .createOrIncrementCount(
                        TEST_SUBJECT_ID, 4070908800L, REAUTHENTICATION, ENTER_MFA_CODE);
        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.INVALID_MFA_CODE_ENTERED));
        mockedNowHelperClass.close();
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
            withReauthTurnedOn();
            when(authenticationAttemptsService.getCountsByJourneyForSubjectIdAndRpPairwiseId(
                            any(), any(), eq(REAUTHENTICATION)))
                    .thenReturn(Map.of(countType, MAX_RETRIES));
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
        when(clientService.getClient(CLIENT_ID)).thenReturn(Optional.of(clientRegistry));
        when(clientService.getClient(TEST_CLIENT_ID)).thenReturn(Optional.of(testClientRegistry));

        return handler.handleRequest(event, context);
    }

    private static Stream<Arguments> codeRequestTypes() {
        return Stream.of(
                Arguments.of(CodeRequestType.MFA_PW_RESET_MFA, JourneyType.PASSWORD_RESET_MFA),
                Arguments.of(CodeRequestType.MFA_REAUTHENTICATION, REAUTHENTICATION),
                Arguments.of(CodeRequestType.MFA_SIGN_IN, JourneyType.SIGN_IN),
                Arguments.of(CodeRequestType.MFA_SIGN_IN, null));
    }

    private void withReauthTurnedOn() {
        when(configurationService.isAuthenticationAttemptsServiceEnabled()).thenReturn(true);
        when(configurationService.supportReauthSignoutEnabled()).thenReturn(true);
    }
}
