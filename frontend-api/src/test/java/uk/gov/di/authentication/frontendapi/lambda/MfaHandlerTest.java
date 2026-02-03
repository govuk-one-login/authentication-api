package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent;
import uk.gov.di.authentication.frontendapi.entity.MfaRequest;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.entity.CodeRequestType;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.NotificationType;
import uk.gov.di.authentication.shared.entity.NotifyRequest;
import uk.gov.di.authentication.shared.entity.PriorityIdentifier;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethod;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.helpers.LocaleHelper.SupportedLanguage;
import uk.gov.di.authentication.shared.helpers.TestUserHelper;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthSessionService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.AwsSqsClient;
import uk.gov.di.authentication.shared.services.CodeGeneratorService;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.InternationalSmsSendLimitService;
import uk.gov.di.authentication.shared.services.SerializationService;
import uk.gov.di.authentication.shared.services.mfa.MFAMethodsService;
import uk.gov.di.authentication.shared.services.mfa.MfaRetrieveFailureReason;
import uk.gov.di.authentication.shared.state.UserContext;
import uk.gov.di.authentication.sharedtest.logging.CaptureLoggingExtension;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.frontendapi.helpers.ApiGatewayProxyRequestHelper.apiRequestEventWithHeadersAndBody;
import static uk.gov.di.authentication.shared.domain.AuditableEvent.AUDIT_EVENT_EXTENSIONS_MFA_METHOD;
import static uk.gov.di.authentication.shared.entity.ErrorResponse.BLOCKED_FOR_SENDING_MFA_OTPS;
import static uk.gov.di.authentication.shared.entity.ErrorResponse.INDEFINITELY_BLOCKED_SENDING_INT_NUMBERS_SMS;
import static uk.gov.di.authentication.shared.entity.ErrorResponse.PHONE_NUMBER_NOT_REGISTERED;
import static uk.gov.di.authentication.shared.entity.ErrorResponse.TOO_MANY_INVALID_MFA_OTPS_ENTERED;
import static uk.gov.di.authentication.shared.entity.ErrorResponse.TOO_MANY_MFA_OTPS_SENT;
import static uk.gov.di.authentication.shared.entity.NotificationType.MFA_SMS;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_PHONE_NUMBER;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.CLIENT_SESSION_ID;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.DI_PERSISTENT_SESSION_ID;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.EMAIL;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.ENCODED_DEVICE_DETAILS;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.INTERNAL_COMMON_SUBJECT_ID;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.IP_ADDRESS;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.SESSION_ID;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.UK_MOBILE_NUMBER;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.VALID_HEADERS;
import static uk.gov.di.authentication.shared.helpers.TxmaAuditHelper.TXMA_AUDIT_ENCODED_HEADER;
import static uk.gov.di.authentication.shared.services.AuditService.MetadataPair.pair;
import static uk.gov.di.authentication.shared.services.CodeStorageService.CODE_BLOCKED_KEY_PREFIX;
import static uk.gov.di.authentication.shared.services.CodeStorageService.CODE_REQUEST_BLOCKED_KEY_PREFIX;
import static uk.gov.di.authentication.sharedtest.logging.LogEventMatcher.withMessageContaining;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;
import static uk.gov.di.authentication.sharedtest.matchers.JsonArgumentMatcher.partiallyContainsJsonString;

class MfaHandlerTest {

    private MfaHandler handler;
    private static final String CODE = "123456";
    private static final long CODE_EXPIRY_TIME = 900;
    private static final long LOCKOUT_DURATION = 799;
    private static final String TEST_CLIENT_ID = "test-client-id";

    private final Context context = mock(Context.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final CodeGeneratorService codeGeneratorService = mock(CodeGeneratorService.class);
    private final CodeStorageService codeStorageService = mock(CodeStorageService.class);
    private final AuthenticationService authenticationService = mock(AuthenticationService.class);
    private final AuditService auditService = mock(AuditService.class);
    private final AwsSqsClient sqsClient = mock(AwsSqsClient.class);
    private final AuthSessionService authSessionService = mock(AuthSessionService.class);
    private final MFAMethodsService mfaMethodsService = mock(MFAMethodsService.class);
    private final TestUserHelper testUserHelper = mock(TestUserHelper.class);
    private final InternationalSmsSendLimitService internationalSmsSendLimitService =
            mock(InternationalSmsSendLimitService.class);
    private static final int MAX_CODE_RETRIES = 6;
    private static final Json objectMapper = SerializationService.getInstance();
    private static final MFAMethod backupAuthAppMethod =
            MFAMethod.authAppMfaMethod(
                    "auth-app-credential-1",
                    true,
                    true,
                    PriorityIdentifier.BACKUP,
                    "auth-app-identifier-1");
    private static final MFAMethod defaultAuthAppMethod =
            MFAMethod.authAppMfaMethod(
                    "auth-app-credential-2",
                    true,
                    true,
                    PriorityIdentifier.DEFAULT,
                    "auth-app-identifier-2");
    private static final String PHONE_NUMBER_FOR_DEFAULT_SMS_METHOD = "+447900000001";
    private static final MFAMethod defaultSmsMethod =
            MFAMethod.smsMfaMethod(
                    true,
                    true,
                    PHONE_NUMBER_FOR_DEFAULT_SMS_METHOD,
                    PriorityIdentifier.DEFAULT,
                    "sms-mfa-identifier-1");
    private static final String PHONE_NUMBER_FOR_BACKUP_SMS_METHOD = "+447900000002";
    private static final MFAMethod backupSmsMethod =
            MFAMethod.smsMfaMethod(
                    true,
                    true,
                    PHONE_NUMBER_FOR_BACKUP_SMS_METHOD,
                    PriorityIdentifier.BACKUP,
                    "sms-mfa-identifier-2");
    private static final String INTERNATIONAL_PHONE_NUMBER = "+33612345678";
    private static final MFAMethod defaultInternationalSmsMethod =
            MFAMethod.smsMfaMethod(
                    true,
                    true,
                    INTERNATIONAL_PHONE_NUMBER,
                    PriorityIdentifier.DEFAULT,
                    "intl-sms-mfa-identifier");

    private final AuditContext AUDIT_CONTEXT =
            new AuditContext(
                    TEST_CLIENT_ID,
                    CLIENT_SESSION_ID,
                    SESSION_ID,
                    INTERNAL_COMMON_SUBJECT_ID,
                    EMAIL,
                    IP_ADDRESS,
                    UK_MOBILE_NUMBER,
                    DI_PERSISTENT_SESSION_ID,
                    Optional.of(ENCODED_DEVICE_DETAILS),
                    new ArrayList<>());

    private final AuthSessionItem authSession =
            new AuthSessionItem()
                    .withSessionId(SESSION_ID)
                    .withEmailAddress(EMAIL)
                    .withInternalCommonSubjectId(INTERNAL_COMMON_SUBJECT_ID)
                    .withClientId(TEST_CLIENT_ID);

    private static final NotifyRequest notifyRequest =
            new NotifyRequest(
                    UK_MOBILE_NUMBER,
                    MFA_SMS,
                    CODE,
                    SupportedLanguage.EN,
                    SESSION_ID,
                    CLIENT_SESSION_ID);

    @RegisterExtension
    private final CaptureLoggingExtension logging = new CaptureLoggingExtension(MfaHandler.class);

    @AfterEach
    void tearDown() {
        assertThat(
                logging.events(), not(hasItem(withMessageContaining(SESSION_ID, TEST_CLIENT_ID))));
    }

    @BeforeEach
    void setUp() {
        when(context.getAwsRequestId()).thenReturn("aws-session-id");
        when(configurationService.getDefaultOtpCodeExpiry()).thenReturn(CODE_EXPIRY_TIME);
        when(configurationService.getCodeMaxRetries()).thenReturn(MAX_CODE_RETRIES);
        when(codeGeneratorService.sixDigitCode()).thenReturn(CODE);
        when(authenticationService.getPhoneNumber(EMAIL)).thenReturn(Optional.of(UK_MOBILE_NUMBER));

        when(mfaMethodsService.getMfaMethods(EMAIL))
                .thenReturn(
                        Result.success(
                                List.of(
                                        MFAMethod.smsMfaMethod(
                                                true,
                                                true,
                                                UK_MOBILE_NUMBER,
                                                PriorityIdentifier.DEFAULT,
                                                "set-up-sms-mfa-identifier"))));

        handler =
                new MfaHandler(
                        configurationService,
                        codeGeneratorService,
                        codeStorageService,
                        authenticationService,
                        auditService,
                        sqsClient,
                        authSessionService,
                        mfaMethodsService,
                        testUserHelper,
                        internationalSmsSendLimitService);
    }

    @Test
    void shouldReturn204ForSuccessfulMfaRequestWhenNonResendCode() throws Json.JsonException {
        usingValidSession();

        when(internationalSmsSendLimitService.canSendSms(UK_MOBILE_NUMBER)).thenReturn(true);

        var body = format("{ \"email\": \"%s\"}", EMAIL);
        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, body);

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        verify(sqsClient)
                .send(
                        argThat(
                                partiallyContainsJsonString(
                                        objectMapper.writeValueAsString(notifyRequest),
                                        "unique_notification_reference")));
        verify(codeStorageService)
                .saveOtpCode(EMAIL.concat(UK_MOBILE_NUMBER), CODE, CODE_EXPIRY_TIME, MFA_SMS);
        assertThat(result, hasStatus(204));

        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.AUTH_MFA_CODE_SENT,
                        AUDIT_CONTEXT
                                .withMetadataItem(pair("journey-type", JourneyType.SIGN_IN))
                                .withMetadataItem(
                                        pair(
                                                "mfa-type",
                                                NotificationType.MFA_SMS
                                                        .getMfaMethodType()
                                                        .getValue()))
                                .withMetadataItem(
                                        pair(
                                                AUDIT_EVENT_EXTENSIONS_MFA_METHOD,
                                                PriorityIdentifier.DEFAULT.name().toLowerCase())));
    }

    @Test
    void shouldReturn204ForSuccessfulMfaRequestForMigratedUser() throws Json.JsonException {
        usingValidSession();

        List<MFAMethod> mfaMethods = List.of(backupAuthAppMethod, defaultSmsMethod);
        when(mfaMethodsService.getMfaMethods(EMAIL)).thenReturn(Result.success(mfaMethods));
        when(internationalSmsSendLimitService.canSendSms(PHONE_NUMBER_FOR_DEFAULT_SMS_METHOD))
                .thenReturn(true);

        var body = format("{ \"email\": \"%s\"}", EMAIL);
        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, body);

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        var notifyRequestWithNumberFromMigratedMethod =
                new NotifyRequest(
                        defaultSmsMethod.getDestination(),
                        MFA_SMS,
                        CODE,
                        SupportedLanguage.EN,
                        SESSION_ID,
                        CLIENT_SESSION_ID);

        verify(sqsClient)
                .send(
                        argThat(
                                partiallyContainsJsonString(
                                        objectMapper.writeValueAsString(
                                                notifyRequestWithNumberFromMigratedMethod),
                                        "unique_notification_reference")));
        verify(codeStorageService)
                .saveOtpCode(
                        EMAIL.concat(PHONE_NUMBER_FOR_DEFAULT_SMS_METHOD),
                        CODE,
                        CODE_EXPIRY_TIME,
                        MFA_SMS);

        assertThat(result, hasStatus(204));

        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.AUTH_MFA_CODE_SENT,
                        AUDIT_CONTEXT
                                .withPhoneNumber(defaultSmsMethod.getDestination())
                                .withMetadataItem(pair("journey-type", JourneyType.SIGN_IN))
                                .withMetadataItem(
                                        pair(
                                                "mfa-type",
                                                NotificationType.MFA_SMS
                                                        .getMfaMethodType()
                                                        .getValue()))
                                .withMetadataItem(
                                        pair(
                                                AUDIT_EVENT_EXTENSIONS_MFA_METHOD,
                                                PriorityIdentifier.DEFAULT.name().toLowerCase())));
    }

    @Test
    void shouldSubmitCorrectAuditEventForSuccessfulMfaRequestUsingBackupSms() {
        usingValidSession();

        List<MFAMethod> mfaMethods = List.of(backupSmsMethod, defaultSmsMethod);
        when(mfaMethodsService.getMfaMethods(EMAIL)).thenReturn(Result.success(mfaMethods));
        when(internationalSmsSendLimitService.canSendSms(PHONE_NUMBER_FOR_BACKUP_SMS_METHOD))
                .thenReturn(true);

        var body =
                format(
                        "{ \"email\": \"%s\", \"mfaMethodId\": \"%s\"}",
                        EMAIL, backupSmsMethod.getMfaIdentifier());
        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, body);

        handler.handleRequest(event, context);

        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.AUTH_MFA_CODE_SENT,
                        AUDIT_CONTEXT
                                .withPhoneNumber(backupSmsMethod.getDestination())
                                .withMetadataItem(pair("journey-type", JourneyType.SIGN_IN))
                                .withMetadataItem(
                                        pair(
                                                "mfa-type",
                                                NotificationType.MFA_SMS
                                                        .getMfaMethodType()
                                                        .getValue()))
                                .withMetadataItem(
                                        pair(
                                                AUDIT_EVENT_EXTENSIONS_MFA_METHOD,
                                                PriorityIdentifier.BACKUP.name().toLowerCase())));
    }

    @Test
    void shouldSendMessageAndStoreCodeForRequestWithIdentifiedMfaMethod()
            throws Json.JsonException {
        usingValidSession();

        List<MFAMethod> mfaMethods = List.of(backupSmsMethod, defaultSmsMethod);
        when(mfaMethodsService.getMfaMethods(EMAIL)).thenReturn(Result.success(mfaMethods));
        when(internationalSmsSendLimitService.canSendSms(PHONE_NUMBER_FOR_BACKUP_SMS_METHOD))
                .thenReturn(true);

        var body =
                format(
                        "{ \"email\": \"%s\", \"mfaMethodId\": \"%s\"}",
                        EMAIL, backupSmsMethod.getMfaIdentifier());
        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, body);

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(204));

        var notifyRequestWithNumberFromMigratedMethod =
                new NotifyRequest(
                        backupSmsMethod.getDestination(),
                        MFA_SMS,
                        CODE,
                        SupportedLanguage.EN,
                        SESSION_ID,
                        CLIENT_SESSION_ID);
        verify(sqsClient)
                .send(
                        argThat(
                                partiallyContainsJsonString(
                                        objectMapper.writeValueAsString(
                                                notifyRequestWithNumberFromMigratedMethod),
                                        "unique_notification_reference")));
        verify(codeStorageService)
                .saveOtpCode(
                        EMAIL.concat(backupSmsMethod.getDestination()),
                        CODE,
                        CODE_EXPIRY_TIME,
                        MFA_SMS);
    }

    private static Stream<List<MFAMethod>> mfaMethodsWithoutSmsDefault() {
        return Stream.of(List.of(defaultAuthAppMethod, backupSmsMethod), List.of(backupSmsMethod));
    }

    @ParameterizedTest
    @MethodSource("mfaMethodsWithoutSmsDefault")
    void shouldReturn400IfMigratedUserDoesNotHaveSmsDefault(
            List<MFAMethod> mfaMethodsWithoutSmsDefault) {
        usingValidSession();
        when(mfaMethodsService.getMfaMethods(EMAIL)).thenReturn(Result.success(List.of()));

        var body = format("{ \"email\": \"%s\"}", EMAIL);
        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, body);

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        verify(sqsClient, never()).send(any());
        verify(codeStorageService, never()).saveOtpCode(any(), any(), anyLong(), any());
        assertThat(result, hasJsonBody(PHONE_NUMBER_NOT_REGISTERED));

        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.AUTH_MFA_MISSING_PHONE_NUMBER,
                        AUDIT_CONTEXT
                                .withPhoneNumber(AuditService.UNKNOWN)
                                .withMetadataItem(pair("journey-type", JourneyType.SIGN_IN))
                                .withMetadataItem(
                                        pair(
                                                "mfa-type",
                                                NotificationType.MFA_SMS
                                                        .getMfaMethodType()
                                                        .getValue())));
    }

    @Test
    void checkAuditEventStillEmittedWhenTICFHeaderNotProvided() {
        usingValidSession();

        when(internationalSmsSendLimitService.canSendSms(UK_MOBILE_NUMBER)).thenReturn(true);

        var headers = new HashMap<String, String>();
        headers.putAll(VALID_HEADERS);
        headers.remove(TXMA_AUDIT_ENCODED_HEADER);

        var body = format("{ \"email\": \"%s\"}", EMAIL);
        var event = apiRequestEventWithHeadersAndBody(headers, body);

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(204));

        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.AUTH_MFA_CODE_SENT,
                        AUDIT_CONTEXT
                                .withTxmaAuditEncoded(Optional.empty())
                                .withMetadataItem(pair("journey-type", JourneyType.SIGN_IN))
                                .withMetadataItem(
                                        pair(
                                                "mfa-type",
                                                NotificationType.MFA_SMS
                                                        .getMfaMethodType()
                                                        .getValue()))
                                .withMetadataItem(
                                        pair(
                                                AUDIT_EVENT_EXTENSIONS_MFA_METHOD,
                                                PriorityIdentifier.DEFAULT.name().toLowerCase())));
    }

    @Test
    void shouldReturn204ForSuccessfulMfaRequestWhenResendingCode() throws Json.JsonException {
        usingValidSession();

        when(internationalSmsSendLimitService.canSendSms(UK_MOBILE_NUMBER)).thenReturn(true);
        when(codeStorageService.getOtpCode(EMAIL.concat(UK_MOBILE_NUMBER), VERIFY_PHONE_NUMBER))
                .thenReturn(Optional.of(CODE));
        NotifyRequest verifyPhoneNumberNotifyRequest =
                new NotifyRequest(
                        UK_MOBILE_NUMBER,
                        VERIFY_PHONE_NUMBER,
                        CODE,
                        SupportedLanguage.EN,
                        SESSION_ID,
                        CLIENT_SESSION_ID);
        var body = format("{ \"email\": \"%s\", \"isResendCodeRequest\": \"%s\"}", EMAIL, "true");
        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, body);

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        verify(sqsClient)
                .send(
                        argThat(
                                partiallyContainsJsonString(
                                        objectMapper.writeValueAsString(
                                                verifyPhoneNumberNotifyRequest),
                                        "unique_notification_reference")));
        verify(codeGeneratorService, never()).sixDigitCode();
        verify(codeStorageService, never())
                .saveOtpCode(
                        any(String.class),
                        any(String.class),
                        anyLong(),
                        any(NotificationType.class));
        verify(authSessionService)
                .updateSession(
                        argThat(
                                session ->
                                        session.getCodeRequestCount(
                                                        NotificationType.MFA_SMS,
                                                        JourneyType.SIGN_IN)
                                                == 1));
        assertThat(result, hasStatus(204));

        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.AUTH_MFA_CODE_SENT,
                        AUDIT_CONTEXT
                                .withMetadataItem(pair("journey-type", JourneyType.SIGN_IN))
                                .withMetadataItem(
                                        pair(
                                                "mfa-type",
                                                NotificationType.MFA_SMS
                                                        .getMfaMethodType()
                                                        .getValue()))
                                .withMetadataItem(
                                        pair(
                                                AUDIT_EVENT_EXTENSIONS_MFA_METHOD,
                                                PriorityIdentifier.DEFAULT.name().toLowerCase())));
    }

    @Test
    void shouldReturn400WhenInvalidMFAJourneyCombination() throws Json.JsonException {
        usingValidSession();

        var body = format("{ \"email\": \"%s\"}", EMAIL);
        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, body);

        MfaRequest test = new MfaRequest(EMAIL, false, JourneyType.PASSWORD_RESET);
        APIGatewayProxyResponseEvent result =
                handler.handleRequestWithUserContext(
                        event, context, test, UserContext.builder(authSession).build());

        assertThat(result, hasStatus(400));

        verifyNoInteractions(auditService);
    }

    @Test
    void shouldReturn400WhenSessionIdIsInvalid() {
        when(authSessionService.getSessionFromRequestHeaders(anyMap()))
                .thenReturn(Optional.empty());
        var body = format("{ \"email\": \"%s\"}", EMAIL);
        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, body);

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));

        verifyNoInteractions(auditService);
    }

    @Test
    void shouldReturn400WhenEmailInSessionDoesNotMatchEmailInRequest() {
        usingValidSession();
        var body = format("{ \"email\": \"%s\"}", "wrong.email@gov.uk");
        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, body);

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));

        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.AUTH_MFA_MISMATCHED_EMAIL,
                        AUDIT_CONTEXT
                                .withEmail("wrong.email@gov.uk")
                                .withPhoneNumber(AuditService.UNKNOWN)
                                .withMetadataItem(pair("journey-type", JourneyType.SIGN_IN))
                                .withMetadataItem(
                                        pair(
                                                "mfa-type",
                                                NotificationType.MFA_SMS
                                                        .getMfaMethodType()
                                                        .getValue())));
    }

    @Test
    void shouldReturn400IfEmailDoesNotHaveUserProfile() {
        usingValidSession();
        when(mfaMethodsService.getMfaMethods(EMAIL))
                .thenReturn(Result.failure(MfaRetrieveFailureReason.USER_DOES_NOT_HAVE_ACCOUNT));

        var body = format("{ \"email\": \"%s\"}", EMAIL);
        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, body);

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        verify(sqsClient, never()).send(any());
        verify(codeStorageService, never()).saveOtpCode(any(), any(), anyLong(), any());
        assertThat(result, hasJsonBody(ErrorResponse.EMAIL_HAS_NO_USER_PROFILE));
    }

    @Test
    void shouldReturnErrorResponseWhenUsersPhoneNumberIsNotStored() {
        usingValidSession();
        when(mfaMethodsService.getMfaMethods(EMAIL)).thenReturn(Result.success(List.of()));

        var body = format("{ \"email\": \"%s\"}", EMAIL);
        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, body);

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(PHONE_NUMBER_NOT_REGISTERED));

        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.AUTH_MFA_MISSING_PHONE_NUMBER,
                        AUDIT_CONTEXT
                                .withPhoneNumber(AuditService.UNKNOWN)
                                .withMetadataItem(pair("journey-type", JourneyType.SIGN_IN))
                                .withMetadataItem(
                                        pair(
                                                "mfa-type",
                                                NotificationType.MFA_SMS
                                                        .getMfaMethodType()
                                                        .getValue())));
    }

    @Test
    void
            shouldReturn204IfUserHasReachedTheOtpRequestLimitsInADifferentLambdaButNotSmsSignInOtpRequestLimit() {
        usingValidSession();
        when(configurationService.getLockoutDuration()).thenReturn(LOCKOUT_DURATION);
        for (int i = 0; i < MAX_CODE_RETRIES; i++) {
            authSession.incrementCodeRequestCount(
                    NotificationType.VERIFY_EMAIL, JourneyType.REGISTRATION);
        }
        when(internationalSmsSendLimitService.canSendSms(UK_MOBILE_NUMBER)).thenReturn(true);

        var body = format("{ \"email\": \"%s\"}", EMAIL);
        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, body);

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertEquals(204, result.getStatusCode());
    }

    @Test
    void shouldReturn204IfUserIsBlockedForRequestingADifferentOtpTypeThanSmsSignInOtpRequest() {
        usingValidSession();

        when(configurationService.getLockoutDuration()).thenReturn(LOCKOUT_DURATION);

        CodeRequestType codeRequestTypeForBlockedOtpRequestType =
                CodeRequestType.getCodeRequestType(
                        NotificationType.VERIFY_EMAIL, JourneyType.REGISTRATION);
        when(codeStorageService.isBlockedForEmail(
                        EMAIL,
                        CODE_REQUEST_BLOCKED_KEY_PREFIX + codeRequestTypeForBlockedOtpRequestType))
                .thenReturn(true);
        when(internationalSmsSendLimitService.canSendSms(UK_MOBILE_NUMBER)).thenReturn(true);

        var body = format("{ \"email\": \"%s\"}", EMAIL);
        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, body);

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertEquals(204, result.getStatusCode());
    }

    @ParameterizedTest
    @MethodSource("smsJourneyTypes")
    void shouldReturn400IfUserHasReachedTheSmsSignInCodeRequestLimit(
            JourneyType journeyType, boolean reauthEnabled) {
        usingValidSession();
        when(configurationService.supportReauthSignoutEnabled()).thenReturn(reauthEnabled);

        when(configurationService.getLockoutDuration()).thenReturn(LOCKOUT_DURATION);
        for (int i = 0; i < MAX_CODE_RETRIES; i++) {
            authSession.incrementCodeRequestCount(MFA_SMS, journeyType);
        }

        var body = format("{ \"email\": \"%s\", \"journeyType\": \"%s\"}", EMAIL, journeyType);
        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, body);

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertEquals(400, result.getStatusCode());
        assertThat(result, hasJsonBody(TOO_MANY_MFA_OTPS_SENT));

        var codeRequestType = CodeRequestType.getCodeRequestType(MFAMethodType.SMS, journeyType);

        checkReauthenticatingUserIsNotBlockedWhenReauthFeatureIsEnabled(journeyType, reauthEnabled);

        checkReauthenticatingUserIsBlockedWhenReauthFeatureIsNotEnabled(
                journeyType, reauthEnabled, codeRequestType);

        checkUserIsBlockedWhenNotReAuthenticating(journeyType, codeRequestType);

        verify(authSessionService)
                .updateSession(
                        argThat(
                                sessionForTestUser ->
                                        sessionForTestUser.getCodeRequestCount(
                                                        NotificationType.MFA_SMS, journeyType)
                                                == 0));

        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.AUTH_MFA_INVALID_CODE_REQUEST,
                        AUDIT_CONTEXT
                                .withPhoneNumber(AuditService.UNKNOWN)
                                .withMetadataItem(pair("journey-type", journeyType))
                                .withMetadataItem(pair("mfa-type", MFAMethodType.SMS.getValue())));
    }

    private void checkUserIsBlockedWhenNotReAuthenticating(
            JourneyType journeyType, CodeRequestType codeRequestType) {
        if (journeyType != JourneyType.REAUTHENTICATION) {
            verify(codeStorageService)
                    .saveBlockedForEmail(
                            EMAIL,
                            CODE_REQUEST_BLOCKED_KEY_PREFIX + codeRequestType,
                            LOCKOUT_DURATION);
        }
    }

    private void checkReauthenticatingUserIsBlockedWhenReauthFeatureIsNotEnabled(
            JourneyType journeyType, boolean reauthEnabled, CodeRequestType codeRequestType) {
        if (journeyType == JourneyType.REAUTHENTICATION && !reauthEnabled) {
            verify(codeStorageService)
                    .saveBlockedForEmail(
                            EMAIL,
                            CODE_REQUEST_BLOCKED_KEY_PREFIX + codeRequestType,
                            LOCKOUT_DURATION);
        }
    }

    private void checkReauthenticatingUserIsNotBlockedWhenReauthFeatureIsEnabled(
            JourneyType journeyType, boolean reauthEnabled) {
        if (journeyType == JourneyType.REAUTHENTICATION && reauthEnabled) {
            verifyNoInteractions(codeStorageService);
        }
    }

    @ParameterizedTest
    @MethodSource("smsJourneyTypes")
    void shouldReturn400IfUserIsBlockedFromRequestingAnyMoreMfaCodes(
            JourneyType journeyType, boolean reauthEnabled) {
        usingValidSession();
        var codeRequestType = CodeRequestType.getCodeRequestType(MFAMethodType.SMS, journeyType);
        when(configurationService.supportReauthSignoutEnabled()).thenReturn(reauthEnabled);
        when(codeStorageService.isBlockedForEmail(
                        EMAIL, CODE_REQUEST_BLOCKED_KEY_PREFIX + codeRequestType))
                .thenReturn(true);

        var body = format("{ \"email\": \"%s\", \"journeyType\": \"%s\"}", EMAIL, journeyType);
        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, body);

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertEquals(400, result.getStatusCode());
        assertThat(result, hasJsonBody(BLOCKED_FOR_SENDING_MFA_OTPS));

        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.AUTH_MFA_INVALID_CODE_REQUEST,
                        AUDIT_CONTEXT
                                .withPhoneNumber(AuditService.UNKNOWN)
                                .withMetadataItem(pair("journey-type", journeyType))
                                .withMetadataItem(pair("mfa-type", MFAMethodType.SMS.getValue())));
    }

    // TODO remove temporary ZDD measure to reference existing deprecated keys when expired
    @Test
    void shouldReturn400IfUserIsBlockedFromRequestingAnyMoreMfaCodesUsingDeprecatedPrefix() {
        var journeyType = JourneyType.SIGN_IN;
        usingValidSession();
        var codeRequestType =
                CodeRequestType.getDeprecatedCodeRequestTypeString(MFAMethodType.SMS, journeyType);
        when(configurationService.supportReauthSignoutEnabled()).thenReturn(true);
        when(codeStorageService.isBlockedForEmail(
                        EMAIL, CODE_REQUEST_BLOCKED_KEY_PREFIX + codeRequestType))
                .thenReturn(true);

        var body = format("{ \"email\": \"%s\", \"journeyType\": \"%s\"}", EMAIL, journeyType);
        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, body);

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertEquals(400, result.getStatusCode());
        assertThat(result, hasJsonBody(BLOCKED_FOR_SENDING_MFA_OTPS));

        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.AUTH_MFA_INVALID_CODE_REQUEST,
                        AUDIT_CONTEXT
                                .withPhoneNumber(AuditService.UNKNOWN)
                                .withMetadataItem(pair("journey-type", journeyType))
                                .withMetadataItem(pair("mfa-type", MFAMethodType.SMS.getValue())));
    }

    @ParameterizedTest
    @MethodSource("smsJourneyTypes")
    void shouldReturn400IfUserIsBlockedFromAttemptingMfaCodes(
            JourneyType journeyType, boolean reauthEnabled) {
        usingValidSession();
        var codeRequestType = CodeRequestType.getCodeRequestType(MFAMethodType.SMS, journeyType);
        when(configurationService.supportReauthSignoutEnabled()).thenReturn(reauthEnabled);
        when(codeStorageService.isBlockedForEmail(EMAIL, CODE_BLOCKED_KEY_PREFIX + codeRequestType))
                .thenReturn(true);

        var body = format("{ \"email\": \"%s\", \"journeyType\": \"%s\"}", EMAIL, journeyType);
        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, body);

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertEquals(400, result.getStatusCode());
        assertThat(result, hasJsonBody(TOO_MANY_INVALID_MFA_OTPS_ENTERED));

        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.AUTH_MFA_INVALID_CODE_REQUEST,
                        AUDIT_CONTEXT
                                .withPhoneNumber(AuditService.UNKNOWN)
                                .withMetadataItem(pair("journey-type", journeyType))
                                .withMetadataItem(pair("mfa-type", MFAMethodType.SMS.getValue())));
    }

    // TODO remove temporary ZDD measure to reference existing deprecated keys when expired
    @ParameterizedTest
    @MethodSource("smsJourneyTypes")
    void shouldReturn400IfUserIsBlockedFromAttemptingMfaCodesUsingDeprecatedPrefix(
            JourneyType journeyType) {
        usingValidSession();
        var codeRequestType =
                CodeRequestType.getDeprecatedCodeRequestTypeString(MFAMethodType.SMS, journeyType);
        when(configurationService.supportReauthSignoutEnabled()).thenReturn(true);
        when(codeStorageService.isBlockedForEmail(EMAIL, CODE_BLOCKED_KEY_PREFIX + codeRequestType))
                .thenReturn(true);

        var body = format("{ \"email\": \"%s\", \"journeyType\": \"%s\"}", EMAIL, journeyType);
        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, body);

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertEquals(400, result.getStatusCode());
        assertThat(result, hasJsonBody(TOO_MANY_INVALID_MFA_OTPS_ENTERED));
    }

    @Test
    void shouldReturn204AndNotSendMessageForSuccessfulMfaRequestOnTestClient()
            throws Json.JsonException {
        usingValidSession();
        when(configurationService.isTestClientsEnabled()).thenReturn(true);
        when(testUserHelper.isTestJourney(any(UserContext.class))).thenReturn(true);
        when(internationalSmsSendLimitService.canSendSms(UK_MOBILE_NUMBER)).thenReturn(true);
        var body = format("{ \"email\": \"%s\"}", EMAIL);
        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, body);

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        verify(sqsClient, never())
                .send(
                        argThat(
                                partiallyContainsJsonString(
                                        objectMapper.writeValueAsString(notifyRequest),
                                        "unique_notification_reference")));
        verify(codeStorageService)
                .saveOtpCode(EMAIL.concat(UK_MOBILE_NUMBER), CODE, CODE_EXPIRY_TIME, MFA_SMS);
        assertThat(result, hasStatus(204));

        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.AUTH_MFA_CODE_SENT_FOR_TEST_CLIENT,
                        AUDIT_CONTEXT
                                .withMetadataItem(pair("journey-type", JourneyType.SIGN_IN))
                                .withMetadataItem(
                                        pair(
                                                "mfa-type",
                                                NotificationType.MFA_SMS
                                                        .getMfaMethodType()
                                                        .getValue()))
                                .withMetadataItem(
                                        pair(
                                                AUDIT_EVENT_EXTENSIONS_MFA_METHOD,
                                                PriorityIdentifier.DEFAULT.name().toLowerCase())));
    }

    @Test
    void shouldUseExistingOtpCodeIfOneExists() throws Json.JsonException {
        usingValidSession();

        when(internationalSmsSendLimitService.canSendSms(UK_MOBILE_NUMBER)).thenReturn(true);
        when(codeStorageService.getOtpCode(any(String.class), any(NotificationType.class)))
                .thenReturn(Optional.of(CODE));

        var body = format("{ \"email\": \"%s\"}", EMAIL);
        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, body);

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        verify(codeGeneratorService, never()).sixDigitCode();
        verify(codeStorageService, never())
                .saveOtpCode(
                        any(String.class),
                        any(String.class),
                        anyLong(),
                        any(NotificationType.class));

        verify(sqsClient)
                .send(
                        argThat(
                                partiallyContainsJsonString(
                                        objectMapper.writeValueAsString(notifyRequest),
                                        "unique_notification_reference")));
        assertThat(result, hasStatus(204));
    }

    @Test
    void shouldGenerateAndSaveOtpCodeIfExistingOneNotFound() throws Json.JsonException {
        usingValidSession();

        when(internationalSmsSendLimitService.canSendSms(UK_MOBILE_NUMBER)).thenReturn(true);
        when(codeStorageService.getOtpCode(any(String.class), any(NotificationType.class)))
                .thenReturn(Optional.empty());

        var body = format("{ \"email\": \"%s\"}", EMAIL);
        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, body);

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        verify(codeGeneratorService).sixDigitCode();
        verify(codeStorageService)
                .saveOtpCode(
                        any(String.class),
                        any(String.class),
                        anyLong(),
                        any(NotificationType.class));
        verify(sqsClient)
                .send(
                        argThat(
                                partiallyContainsJsonString(
                                        objectMapper.writeValueAsString(notifyRequest),
                                        "unique_notification_reference")));
        assertThat(result, hasStatus(204));
    }

    @ParameterizedTest
    @MethodSource("mfaJourneyTypes")
    void shouldReturn400WhenInternationalNumberHasHitSendLimit(JourneyType journeyType) {
        usingValidSession();

        when(mfaMethodsService.getMfaMethods(EMAIL))
                .thenReturn(Result.success(List.of(defaultInternationalSmsMethod)));
        when(internationalSmsSendLimitService.canSendSms(INTERNATIONAL_PHONE_NUMBER))
                .thenReturn(false);

        var body =
                format(
                        "{ \"email\": \"%s\", \"isResendCodeRequest\": false, \"journeyType\": \"%s\"}",
                        EMAIL, journeyType);
        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, body);

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(INDEFINITELY_BLOCKED_SENDING_INT_NUMBERS_SMS));
        verify(sqsClient, never()).send(any());
        verify(codeStorageService, never()).saveOtpCode(any(), any(), anyLong(), any());
    }

    @ParameterizedTest
    @MethodSource("mfaJourneyTypes")
    void shouldReturn204WhenInternationalNumberIsBelowSendLimit(JourneyType journeyType)
            throws Json.JsonException {
        usingValidSession();

        when(mfaMethodsService.getMfaMethods(EMAIL))
                .thenReturn(Result.success(List.of(defaultInternationalSmsMethod)));
        when(internationalSmsSendLimitService.canSendSms(INTERNATIONAL_PHONE_NUMBER))
                .thenReturn(true);

        var body =
                format(
                        "{ \"email\": \"%s\", \"isResendCodeRequest\": false, \"journeyType\": \"%s\"}",
                        EMAIL, journeyType);
        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, body);

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(204));
        verify(internationalSmsSendLimitService).canSendSms(INTERNATIONAL_PHONE_NUMBER);
        verify(sqsClient).send(any());
        verify(codeStorageService).saveOtpCode(any(), any(), anyLong(), any());
    }

    @ParameterizedTest
    @MethodSource("mfaJourneyTypes")
    void shouldReturn204ForDomesticNumberRegardlessOfLimit(JourneyType journeyType)
            throws Json.JsonException {
        usingValidSession();

        when(mfaMethodsService.getMfaMethods(EMAIL))
                .thenReturn(Result.success(List.of(defaultSmsMethod)));
        when(internationalSmsSendLimitService.canSendSms(PHONE_NUMBER_FOR_DEFAULT_SMS_METHOD))
                .thenReturn(true);

        var body =
                format(
                        "{ \"email\": \"%s\", \"isResendCodeRequest\": false, \"journeyType\": \"%s\"}",
                        EMAIL, journeyType);
        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, body);

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(204));
        verify(internationalSmsSendLimitService).canSendSms(PHONE_NUMBER_FOR_DEFAULT_SMS_METHOD);
        verify(sqsClient).send(any());
        verify(codeStorageService).saveOtpCode(any(), any(), anyLong(), any());
    }

    private void usingValidSession() {
        when(authSessionService.getSessionFromRequestHeaders(anyMap()))
                .thenReturn(Optional.of(authSession));
    }

    private static Stream<Arguments> smsJourneyTypes() {
        return Stream.of(
                Arguments.of(JourneyType.PASSWORD_RESET_MFA, false),
                Arguments.of(JourneyType.SIGN_IN, false),
                Arguments.of(JourneyType.REAUTHENTICATION, false),
                Arguments.of(JourneyType.PASSWORD_RESET_MFA, true),
                Arguments.of(JourneyType.SIGN_IN, true),
                Arguments.of(JourneyType.REAUTHENTICATION, true));
    }

    private static Stream<Arguments> mfaJourneyTypes() {
        return Stream.of(
                Arguments.of(JourneyType.SIGN_IN),
                Arguments.of(JourneyType.PASSWORD_RESET_MFA),
                Arguments.of(JourneyType.REAUTHENTICATION));
    }
}
