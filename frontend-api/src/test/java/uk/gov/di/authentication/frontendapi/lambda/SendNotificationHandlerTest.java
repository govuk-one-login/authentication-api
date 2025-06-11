package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import software.amazon.awssdk.core.exception.SdkClientException;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.CodeRequestType;
import uk.gov.di.authentication.shared.entity.EmailCheckResultStore;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.NotificationType;
import uk.gov.di.authentication.shared.entity.NotifyRequest;
import uk.gov.di.authentication.shared.helpers.CommonTestVariables;
import uk.gov.di.authentication.shared.helpers.LocaleHelper.SupportedLanguage;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.helpers.PhoneNumberHelper;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthSessionService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.AwsSqsClient;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.CodeGeneratorService;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoEmailCheckResultService;
import uk.gov.di.authentication.shared.services.SerializationService;
import uk.gov.di.authentication.sharedtest.logging.CaptureLoggingExtension;

import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Stream;

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_ACCOUNT_RECOVERY_EMAIL_CODE_SENT;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_ACCOUNT_RECOVERY_EMAIL_CODE_SENT_FOR_TEST_CLIENT;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_ACCOUNT_RECOVERY_EMAIL_INVALID_CODE_REQUEST;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_EMAIL_CODE_SENT;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_EMAIL_CODE_SENT_FOR_TEST_CLIENT;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_EMAIL_INVALID_CODE_REQUEST;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_PHONE_CODE_SENT;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_PHONE_INVALID_CODE_REQUEST;
import static uk.gov.di.authentication.frontendapi.helpers.ApiGatewayProxyRequestHelper.apiRequestEventWithHeadersAndBody;
import static uk.gov.di.authentication.shared.domain.RequestHeaders.CLIENT_SESSION_ID_HEADER;
import static uk.gov.di.authentication.shared.domain.RequestHeaders.SESSION_ID_HEADER;
import static uk.gov.di.authentication.shared.entity.NotificationType.MFA_SMS;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_CHANGE_HOW_GET_SECURITY_CODES;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_EMAIL;
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
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.VALID_HEADERS_WITHOUT_AUDIT_ENCODED;
import static uk.gov.di.authentication.shared.services.CodeStorageService.CODE_BLOCKED_KEY_PREFIX;
import static uk.gov.di.authentication.shared.services.CodeStorageService.CODE_REQUEST_BLOCKED_KEY_PREFIX;
import static uk.gov.di.authentication.sharedtest.logging.LogEventMatcher.withMessageContaining;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;
import static uk.gov.di.authentication.sharedtest.matchers.JsonArgumentMatcher.partiallyContainsJsonString;

class SendNotificationHandlerTest {

    private static final String TEST_SIX_DIGIT_CODE = "123456";
    private static final long CODE_EXPIRY_TIME = 900;
    private static final long LOCKOUT_DURATION = 799;
    private static final String CLIENT_ID = "client-id";
    private static final String TEST_CLIENT_ID = "test-client-id";
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final AwsSqsClient emailSqsClient = mock(AwsSqsClient.class);
    private final AwsSqsClient pendingEmailCheckSqsClient = mock(AwsSqsClient.class);
    private final AuthSessionService authSessionService = mock(AuthSessionService.class);
    private final CodeGeneratorService codeGeneratorService = mock(CodeGeneratorService.class);
    private final CodeStorageService codeStorageService = mock(CodeStorageService.class);
    private final ClientService clientService = mock(ClientService.class);
    private final AuthenticationService authenticationService = mock(AuthenticationService.class);
    private final DynamoEmailCheckResultService dynamoEmailCheckResultService =
            mock(DynamoEmailCheckResultService.class);
    private final AuditService auditService = mock(AuditService.class);
    private final ClientRegistry clientRegistry =
            new ClientRegistry().withTestClient(false).withClientID(CLIENT_ID);
    private final ClientRegistry testClientRegistry =
            new ClientRegistry()
                    .withTestClient(true)
                    .withClientID(TEST_CLIENT_ID)
                    .withTestClientEmailAllowlist(List.of(EMAIL));

    private final Context context = mock(Context.class);
    private static final Json objectMapper = SerializationService.getInstance();

    private final AuthSessionItem authSession =
            new AuthSessionItem()
                    .withSessionId(SESSION_ID)
                    .withInternalCommonSubjectId(INTERNAL_COMMON_SUBJECT_ID)
                    .withEmailAddress(EMAIL)
                    .withClientId(CLIENT_ID);

    private final AuditContext auditContext =
            new AuditContext(
                    CLIENT_ID,
                    CLIENT_SESSION_ID,
                    SESSION_ID,
                    INTERNAL_COMMON_SUBJECT_ID,
                    EMAIL,
                    IP_ADDRESS,
                    AuditService.UNKNOWN,
                    DI_PERSISTENT_SESSION_ID,
                    Optional.of(ENCODED_DEVICE_DETAILS));

    private final SendNotificationHandler handler =
            new SendNotificationHandler(
                    configurationService,
                    clientService,
                    authenticationService,
                    emailSqsClient,
                    pendingEmailCheckSqsClient,
                    codeGeneratorService,
                    codeStorageService,
                    dynamoEmailCheckResultService,
                    auditService,
                    authSessionService);

    @RegisterExtension
    private final CaptureLoggingExtension logging =
            new CaptureLoggingExtension(SendNotificationHandler.class);

    @AfterEach
    void tearDown() {
        assertThat(
                logging.events(),
                not(
                        hasItem(
                                withMessageContaining(
                                        SESSION_ID,
                                        CLIENT_ID,
                                        TEST_CLIENT_ID,
                                        EMAIL,
                                        CommonTestVariables.UK_MOBILE_NUMBER))));
    }

    @BeforeEach
    void setup() {
        when(configurationService.getDefaultOtpCodeExpiry()).thenReturn(CODE_EXPIRY_TIME);
        when(configurationService.isEmailCheckEnabled()).thenReturn(true);
        when(configurationService.getEmailAccountCreationOtpCodeExpiry())
                .thenReturn(CODE_EXPIRY_TIME);
        when(configurationService.getLockoutDuration()).thenReturn(LOCKOUT_DURATION);
        when(codeGeneratorService.sixDigitCode()).thenReturn(TEST_SIX_DIGIT_CODE);
        when(configurationService.getCodeMaxRetries()).thenReturn(6);
        when(configurationService.getEnvironment()).thenReturn("unit-test");
        when(clientService.getClient(CLIENT_ID)).thenReturn(Optional.of(clientRegistry));
        when(clientService.getClient(TEST_CLIENT_ID)).thenReturn(Optional.of(testClientRegistry));
    }

    private static Stream<Arguments> notificationTypeAndJourneyTypeArgs() {
        return Stream.of(
                Arguments.of(VERIFY_EMAIL, JourneyType.REGISTRATION, true),
                Arguments.of(VERIFY_EMAIL, JourneyType.REGISTRATION, false),
                Arguments.of(
                        VERIFY_CHANGE_HOW_GET_SECURITY_CODES, JourneyType.ACCOUNT_RECOVERY, true),
                Arguments.of(
                        VERIFY_CHANGE_HOW_GET_SECURITY_CODES, JourneyType.ACCOUNT_RECOVERY, false));
    }

    @ParameterizedTest
    @MethodSource("notificationTypeAndJourneyTypeArgs")
    void shouldReturn204ForValidEmailOtpRequest(
            NotificationType notificationType, JourneyType journeyType, boolean ticfHeaderPresent)
            throws Json.JsonException {
        usingValidSession();

        Date mockedDate = new Date();
        UUID mockedUUID = UUID.fromString("5fc03087-d265-11e7-b8c6-83e29cd24f4c");
        try (MockedStatic<NowHelper> mockedNowHelperClass = Mockito.mockStatic(NowHelper.class)) {
            try (MockedStatic<UUID> mockedUUIDClass = Mockito.mockStatic(UUID.class)) {
                mockedNowHelperClass.when(NowHelper::now).thenReturn(mockedDate);
                mockedUUIDClass.when(UUID::randomUUID).thenReturn(mockedUUID);

                var body =
                        format(
                                "{ \"email\": \"%s\", \"notificationType\": \"%s\", \"journeyType\": \"%s\" }",
                                EMAIL, notificationType, journeyType);
                var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, body);

                var expectedAuditContext = auditContext;

                if (!ticfHeaderPresent) {
                    event.setHeaders(VALID_HEADERS_WITHOUT_AUDIT_ENCODED);
                    expectedAuditContext = auditContext.withTxmaAuditEncoded(Optional.empty());
                }

                var result = handler.handleRequest(event, context);

                assertEquals(204, result.getStatusCode());
                verify(emailSqsClient)
                        .send(
                                objectMapper.writeValueAsString(
                                        new NotifyRequest(
                                                EMAIL,
                                                notificationType,
                                                TEST_SIX_DIGIT_CODE,
                                                SupportedLanguage.EN,
                                                SESSION_ID,
                                                CLIENT_SESSION_ID)));
                if (notificationType == NotificationType.VERIFY_EMAIL
                        && journeyType == JourneyType.REGISTRATION) {
                    verify(pendingEmailCheckSqsClient)
                            .send(
                                    format(
                                            "{\"userId\":\"%s\",\"requestReference\":\"%s\",\"emailAddress\":\"%s\",\"userSessionId\":\"%s\",\"govukSigninJourneyId\":\"%s\",\"persistentSessionId\":\"%s\",\"ipAddress\":\"%s\",\"journeyType\":\"%s\",\"timeOfInitialRequest\":%d,\"isTestUserRequest\":%b}",
                                            AuditService.UNKNOWN,
                                            mockedUUID,
                                            EMAIL,
                                            SESSION_ID,
                                            CLIENT_SESSION_ID,
                                            DI_PERSISTENT_SESSION_ID,
                                            IP_ADDRESS,
                                            JourneyType.REGISTRATION,
                                            mockedDate.toInstant().toEpochMilli(),
                                            false));
                } else {
                    verifyNoInteractions(pendingEmailCheckSqsClient);
                }
                verify(codeGeneratorService).sixDigitCode();
                verify(codeStorageService).getOtpCode(EMAIL, notificationType);
                verify(codeStorageService)
                        .saveOtpCode(
                                EMAIL, TEST_SIX_DIGIT_CODE, CODE_EXPIRY_TIME, notificationType);
                verify(codeStorageService).getOtpCode(EMAIL, notificationType);

                verify(authSessionService)
                        .updateSession(
                                argThat(
                                        authSession ->
                                                authSession.getCodeRequestCount(
                                                                notificationType, journeyType)
                                                        == 1));
                verify(auditService)
                        .submitAuditEvent(
                                notificationType.equals(VERIFY_EMAIL)
                                        ? AUTH_EMAIL_CODE_SENT
                                        : AUTH_ACCOUNT_RECOVERY_EMAIL_CODE_SENT,
                                expectedAuditContext);
            }
        }
    }

    private static Stream<Arguments> requestEmailCheckPermutations() {
        return Stream.of(Arguments.of(true, false), Arguments.of(false, true));
    }

    @ParameterizedTest
    @MethodSource("requestEmailCheckPermutations")
    void shouldCorrectlyRequestEmailCheck(
            boolean cachedResultAlreadyExists, boolean expectedCheckRequested) {
        usingValidSession();

        if (cachedResultAlreadyExists) {
            when(dynamoEmailCheckResultService.getEmailCheckStore(EMAIL))
                    .thenReturn(Optional.of(new EmailCheckResultStore().withEmail(EMAIL)));
        }

        Date mockedDate = new Date();
        UUID mockedUUID = UUID.fromString("5fc03087-d265-11e7-b8c6-83e29cd24f4c");
        try (MockedStatic<NowHelper> mockedNowHelperClass = Mockito.mockStatic(NowHelper.class);
                MockedStatic<UUID> mockedUUIDClass = Mockito.mockStatic(UUID.class)) {
            mockedNowHelperClass.when(NowHelper::now).thenReturn(mockedDate);
            mockedUUIDClass.when(UUID::randomUUID).thenReturn(mockedUUID);

            var body =
                    format(
                            "{ \"email\": \"%s\", \"notificationType\": \"%s\", \"journeyType\": \"%s\" }",
                            EMAIL, NotificationType.VERIFY_EMAIL, JourneyType.REGISTRATION);
            var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, body);

            handler.handleRequest(event, context);

            if (expectedCheckRequested) {
                verify(pendingEmailCheckSqsClient)
                        .send(
                                format(
                                        "{\"userId\":\"%s\",\"requestReference\":\"%s\",\"emailAddress\":\"%s\",\"userSessionId\":\"%s\",\"govukSigninJourneyId\":\"%s\",\"persistentSessionId\":\"%s\",\"ipAddress\":\"%s\",\"journeyType\":\"%s\",\"timeOfInitialRequest\":%d,\"isTestUserRequest\":%b}",
                                        AuditService.UNKNOWN,
                                        mockedUUID,
                                        EMAIL,
                                        SESSION_ID,
                                        CLIENT_SESSION_ID,
                                        DI_PERSISTENT_SESSION_ID,
                                        IP_ADDRESS,
                                        JourneyType.REGISTRATION,
                                        mockedDate.toInstant().toEpochMilli(),
                                        false));
            } else {
                verifyNoInteractions(pendingEmailCheckSqsClient);
            }
        }
    }

    @ParameterizedTest
    @MethodSource("notificationTypeAndJourneyTypeArgs")
    void shouldReturn204AndNotEnqueuePendingEmailCheckWhenFeatureFlagDisabled(
            NotificationType notificationType, JourneyType journeyType) throws Json.JsonException {
        when(configurationService.isEmailCheckEnabled()).thenReturn(false);
        usingValidSession();

        var body =
                format(
                        "{ \"email\": \"%s\", \"notificationType\": \"%s\", \"journeyType\": \"%s\" }",
                        EMAIL, notificationType, journeyType);
        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, body);

        var result = handler.handleRequest(event, context);

        assertEquals(204, result.getStatusCode());
        verifyNoInteractions(pendingEmailCheckSqsClient);
    }

    @ParameterizedTest
    @EnumSource(
            value = NotificationType.class,
            names = {"VERIFY_EMAIL", "VERIFY_CHANGE_HOW_GET_SECURITY_CODES"})
    void shouldReturn204AndGenerateNewOtpCodeIfOneExistsWhenNewCodeRequested(
            NotificationType notificationType) throws Json.JsonException {
        usingValidSession();

        var body =
                format(
                        "{ \"email\": \"%s\", \"notificationType\": \"%s\", \"requestNewCode\": \"%s\", \"journeyType\": \"%s\" }",
                        EMAIL, notificationType, true, JourneyType.ACCOUNT_RECOVERY);
        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, body);

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(204));
        verify(codeGeneratorService).sixDigitCode();
        verify(codeStorageService, never()).getOtpCode(any(), any());
        verify(codeStorageService)
                .saveOtpCode(EMAIL, TEST_SIX_DIGIT_CODE, CODE_EXPIRY_TIME, notificationType);
        verify(emailSqsClient)
                .send(
                        argThat(
                                partiallyContainsJsonString(
                                        objectMapper.writeValueAsString(
                                                new NotifyRequest(
                                                        EMAIL,
                                                        notificationType,
                                                        TEST_SIX_DIGIT_CODE,
                                                        SupportedLanguage.EN,
                                                        SESSION_ID,
                                                        CLIENT_SESSION_ID)),
                                        "unique_notification_reference")));

        var expectedEvent =
                notificationType.equals(VERIFY_EMAIL)
                        ? AUTH_EMAIL_CODE_SENT
                        : AUTH_ACCOUNT_RECOVERY_EMAIL_CODE_SENT;
        verify(auditService).submitAuditEvent(expectedEvent, auditContext);
    }

    @Test
    void shouldReturn204AndUseExistingOtpCodeIfOneExistsForVerifyPhoneRequest()
            throws Json.JsonException {
        usingValidSession();
        when(codeStorageService.getOtpCode(any(String.class), any(NotificationType.class)))
                .thenReturn(Optional.of(TEST_SIX_DIGIT_CODE));

        var body =
                format(
                        "{ \"email\": \"%s\", \"notificationType\": \"%s\", \"phoneNumber\": \"%s\", \"journeyType\": \"%s\" }",
                        EMAIL,
                        VERIFY_PHONE_NUMBER,
                        CommonTestVariables.UK_MOBILE_NUMBER,
                        JourneyType.REGISTRATION);
        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, body);

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(204));
        verify(codeGeneratorService, never()).sixDigitCode();
        verify(codeStorageService, never())
                .saveOtpCode(
                        any(String.class),
                        any(String.class),
                        anyLong(),
                        any(NotificationType.class));

        verify(emailSqsClient)
                .send(
                        argThat(
                                partiallyContainsJsonString(
                                        objectMapper.writeValueAsString(
                                                new NotifyRequest(
                                                        CommonTestVariables.UK_MOBILE_NUMBER,
                                                        VERIFY_PHONE_NUMBER,
                                                        TEST_SIX_DIGIT_CODE,
                                                        SupportedLanguage.EN,
                                                        SESSION_ID,
                                                        CLIENT_SESSION_ID)),
                                        "unique_notification_reference")));
        verify(auditService)
                .submitAuditEvent(
                        AUTH_PHONE_CODE_SENT, auditContext.withPhoneNumber(UK_MOBILE_NUMBER));
    }

    @ParameterizedTest
    @MethodSource("notificationTypeAndJourneyTypeArgs")
    void shouldReturn204AndNotPutMessageOnQueueForAValidRequestUsingTestClientWithAllowedEmail(
            NotificationType notificationType, JourneyType journeyType) {
        usingValidSession(TEST_CLIENT_ID);
        when(configurationService.isTestClientsEnabled()).thenReturn(true);

        var body =
                format(
                        "{ \"email\": \"%s\", \"notificationType\": \"%s\", \"journeyType\": \"%s\" }",
                        EMAIL, notificationType, journeyType);
        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, body);

        var result = handler.handleRequest(event, context);

        assertEquals(204, result.getStatusCode());
        verifyNoInteractions(emailSqsClient);
        verify(codeStorageService).getOtpCode(EMAIL, notificationType);
        verify(codeStorageService)
                .saveOtpCode(EMAIL, TEST_SIX_DIGIT_CODE, CODE_EXPIRY_TIME, notificationType);
        verify(authSessionService)
                .updateSession(
                        argThat(
                                authSession ->
                                        authSession.getCodeRequestCount(
                                                        notificationType, journeyType)
                                                == 1));

        var testClientAuditContext = auditContext.withClientId(TEST_CLIENT_ID);

        verify(auditService)
                .submitAuditEvent(
                        notificationType.equals(VERIFY_EMAIL)
                                ? AUTH_EMAIL_CODE_SENT_FOR_TEST_CLIENT
                                : AUTH_ACCOUNT_RECOVERY_EMAIL_CODE_SENT_FOR_TEST_CLIENT,
                        testClientAuditContext);
    }

    @ParameterizedTest
    @MethodSource("notificationTypeAndJourneyTypeArgs")
    void shouldReturn400IfInvalidSessionProvided(
            NotificationType notificationType, JourneyType journeyType) {
        var body =
                format(
                        "{ \"email\": \"%s\", \"notificationType\": \"%s\", \"journeyType\": \"%s\" }",
                        EMAIL, notificationType, journeyType);
        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, body);

        var result = handler.handleRequest(event, context);

        assertEquals(400, result.getStatusCode());
        verifyNoInteractions(emailSqsClient);
        verifyNoInteractions(codeStorageService);
        verify(authSessionService, never())
                .updateSession(
                        argThat(
                                authSessionItem ->
                                        authSessionItem.getCodeRequestCount(
                                                        notificationType, journeyType)
                                                == 1));
        verifyNoInteractions(auditService);
    }

    private static Stream<Arguments> sendNotificationPhoneNumberFails() {
        return Stream.of(
                Arguments.of("0123456789A", "production", false),
                Arguments.of("0123456789A", "production", true),
                Arguments.of("07700900000", "production", false),
                Arguments.of("+447700900111", "production", false));
    }

    @ParameterizedTest
    @MethodSource("sendNotificationPhoneNumberFails")
    void shouldReturn400WhenPhoneNumberFailsValidation(
            String phoneNumber, String environment, boolean isSmokeTest) {
        authSession.setIsSmokeTest(isSmokeTest);
        usingValidSession();
        when(configurationService.getEnvironment()).thenReturn(environment);

        var body =
                format(
                        "{ \"email\": \"%s\", \"notificationType\": \"%s\", \"phoneNumber\": \"%s\", \"journeyType\": \"%s\" }",
                        EMAIL, VERIFY_PHONE_NUMBER, phoneNumber, JourneyType.REGISTRATION);
        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, body);

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.INVALID_PHONE_NUMBER));
        verifyNoInteractions(emailSqsClient);
        verifyNoInteractions(auditService);
    }

    @Test
    void shouldReturn400IfRequestIsMissingEmail() {
        usingValidSession();

        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, "{ }");

        var result = handler.handleRequest(event, context);

        assertEquals(400, result.getStatusCode());
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1001));
        verifyNoInteractions(emailSqsClient);
        verifyNoInteractions(codeStorageService);
        verifyNoInteractions(auditService);
    }

    @ParameterizedTest
    @EnumSource(
            value = NotificationType.class,
            names = {"VERIFY_EMAIL", "VERIFY_CHANGE_HOW_GET_SECURITY_CODES"})
    void shouldReturn500IfMessageCannotBeSentToQueue(NotificationType notificationType)
            throws Json.JsonException {
        usingValidSession();
        Mockito.doThrow(SdkClientException.class)
                .when(emailSqsClient)
                .send(
                        argThat(
                                partiallyContainsJsonString(
                                        objectMapper.writeValueAsString(
                                                new NotifyRequest(
                                                        EMAIL,
                                                        notificationType,
                                                        TEST_SIX_DIGIT_CODE,
                                                        SupportedLanguage.EN,
                                                        SESSION_ID,
                                                        CLIENT_SESSION_ID)),
                                        "unique_notification_reference")));

        var body =
                format(
                        "{ \"email\": \"%s\", \"notificationType\": \"%s\", \"journeyType\": \"%s\" }",
                        EMAIL, notificationType, JourneyType.REGISTRATION);
        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, body);

        var result = handler.handleRequest(event, context);

        assertEquals(500, result.getStatusCode());
        assertTrue(result.getBody().contains("Error sending message to queue"));
        verifyNoInteractions(auditService);
    }

    @Test
    void shouldReturn400WhenInvalidNotificationType() {
        usingValidSession();

        var body =
                format(
                        "{ \"email\": \"%s\", \"notificationType\": \"%s\" }",
                        EMAIL, "VERIFY_PASSWORD");
        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, body);

        var result = handler.handleRequest(event, context);

        assertEquals(400, result.getStatusCode());
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1001));

        verifyNoInteractions(emailSqsClient);
        verifyNoInteractions(auditService);
        verifyNoInteractions(codeStorageService);
    }

    private static Stream<String> validPhoneNumbers() {
        return Stream.of(
                "+447316763843",
                "+4407316763843",
                "+33645453322",
                "+447316763843",
                "+33645453322",
                "+33645453322",
                "07911123456",
                "07123456789",
                "07755551084");
    }

    @ParameterizedTest
    @MethodSource("validPhoneNumbers")
    void shouldReturn204ForValidVerifyPhoneNumberRequest(String phoneNumber)
            throws Json.JsonException {
        usingValidSession();

        var formattedPhoneNumber = PhoneNumberHelper.formatPhoneNumber(phoneNumber);
        var body =
                format(
                        "{ \"email\": \"%s\", \"notificationType\": \"%s\", \"phoneNumber\": \"%s\", \"journeyType\": \"%s\" }",
                        EMAIL, VERIFY_PHONE_NUMBER, phoneNumber, JourneyType.REGISTRATION);
        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, body);

        var result = handler.handleRequest(event, context);

        assertEquals(204, result.getStatusCode());
        verify(codeGeneratorService).sixDigitCode();
        verify(codeStorageService)
                .getOtpCode(EMAIL.concat(formattedPhoneNumber), VERIFY_PHONE_NUMBER);
        verify(codeStorageService)
                .saveOtpCode(
                        EMAIL.concat(formattedPhoneNumber),
                        TEST_SIX_DIGIT_CODE,
                        CODE_EXPIRY_TIME,
                        VERIFY_PHONE_NUMBER);
        verify(emailSqsClient)
                .send(
                        argThat(
                                partiallyContainsJsonString(
                                        objectMapper.writeValueAsString(
                                                new NotifyRequest(
                                                        phoneNumber,
                                                        VERIFY_PHONE_NUMBER,
                                                        TEST_SIX_DIGIT_CODE,
                                                        SupportedLanguage.EN,
                                                        SESSION_ID,
                                                        CLIENT_SESSION_ID)),
                                        "unique_notification_reference")));
        verify(auditService)
                .submitAuditEvent(AUTH_PHONE_CODE_SENT, auditContext.withPhoneNumber(phoneNumber));
    }

    @Test
    void shouldReturn400ForVerifyPhoneNumberRequestWhenPhoneNumberIsMissing() {
        usingValidSession();

        var body =
                format(
                        "{ \"email\": \"%s\", \"notificationType\": \"%s\", \"journeyType\": \"%s\" }",
                        EMAIL, VERIFY_PHONE_NUMBER, JourneyType.REGISTRATION);
        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, body);

        var result = handler.handleRequest(event, context);

        assertEquals(400, result.getStatusCode());
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1011));
        verifyNoInteractions(emailSqsClient);
        verifyNoInteractions(auditService);
    }

    private static Stream<Arguments> contrastingNotificationTypeAndJourneyTypeArgs() {
        return Stream.of(
                Arguments.of(MFA_SMS, JourneyType.SIGN_IN, VERIFY_EMAIL, JourneyType.REGISTRATION),
                Arguments.of(
                        VERIFY_PHONE_NUMBER,
                        JourneyType.REGISTRATION,
                        VERIFY_EMAIL,
                        JourneyType.REGISTRATION),
                Arguments.of(
                        VERIFY_EMAIL,
                        JourneyType.REGISTRATION,
                        VERIFY_PHONE_NUMBER,
                        JourneyType.REGISTRATION),
                Arguments.of(
                        VERIFY_EMAIL,
                        JourneyType.REGISTRATION,
                        VERIFY_CHANGE_HOW_GET_SECURITY_CODES,
                        JourneyType.ACCOUNT_RECOVERY),
                Arguments.of(
                        VERIFY_CHANGE_HOW_GET_SECURITY_CODES,
                        JourneyType.ACCOUNT_RECOVERY,
                        VERIFY_EMAIL,
                        JourneyType.REGISTRATION));
    }

    @ParameterizedTest
    @MethodSource("contrastingNotificationTypeAndJourneyTypeArgs")
    void
            shouldReturn204IfUserHasReachedTheOtpRequestLimitForADifferentOtpTypeToThatCurrentlyBeingRequested(
                    NotificationType notificationTypeOne,
                    JourneyType journeyTypeOne,
                    NotificationType notificationTypeTwo,
                    JourneyType journeyTypeTwo) {
        maxOutCodeRequestCount(notificationTypeOne, journeyTypeOne);
        usingValidSession();

        var body =
                format(
                        "{ \"email\": \"%s\", \"notificationType\": \"%s\", \"phoneNumber\": \"%s\", \"journeyType\": \"%s\" }",
                        EMAIL,
                        notificationTypeTwo,
                        CommonTestVariables.UK_MOBILE_NUMBER,
                        journeyTypeTwo);
        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, body);

        var result = handler.handleRequest(event, context);

        assertEquals(204, result.getStatusCode());
    }

    @ParameterizedTest
    @MethodSource("contrastingNotificationTypeAndJourneyTypeArgs")
    void shouldReturn204IfUserIsBlockedForRequestingADifferentOtpTypeToThatCurrentlyBeingRequested(
            NotificationType notificationTypeOne,
            JourneyType journeyTypeOne,
            NotificationType notificationTypeTwo,
            JourneyType journeyTypeTwo) {
        CodeRequestType codeRequestTypeForBlockedOtpRequestType =
                CodeRequestType.getCodeRequestType(notificationTypeOne, journeyTypeOne);
        when(codeStorageService.isBlockedForEmail(
                        EMAIL,
                        CODE_REQUEST_BLOCKED_KEY_PREFIX + codeRequestTypeForBlockedOtpRequestType))
                .thenReturn(true);

        usingValidSession();

        var body =
                format(
                        "{ \"email\": \"%s\", \"notificationType\": \"%s\", \"phoneNumber\": \"%s\", \"journeyType\": \"%s\" }",
                        EMAIL,
                        notificationTypeTwo,
                        CommonTestVariables.UK_MOBILE_NUMBER,
                        journeyTypeTwo);
        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, body);

        var result = handler.handleRequest(event, context);

        assertEquals(204, result.getStatusCode());
    }

    @Test
    void shouldReturn400IfUserHasReachedTheRegistrationEmailOtpRequestLimit() {
        maxOutCodeRequestCount(VERIFY_EMAIL, JourneyType.REGISTRATION);
        usingValidSession();

        var body =
                format(
                        "{ \"email\": \"%s\", \"notificationType\": \"%s\", \"journeyType\": \"%s\" }",
                        EMAIL, VERIFY_EMAIL, JourneyType.REGISTRATION);
        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, body);

        var result = handler.handleRequest(event, context);

        assertEquals(400, result.getStatusCode());
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1029));
        verify(codeStorageService)
                .saveBlockedForEmail(
                        EMAIL,
                        CODE_REQUEST_BLOCKED_KEY_PREFIX + CodeRequestType.EMAIL_REGISTRATION,
                        LOCKOUT_DURATION);
        verify(codeStorageService, never())
                .saveOtpCode(EMAIL, TEST_SIX_DIGIT_CODE, CODE_EXPIRY_TIME, VERIFY_EMAIL);
        verifyNoInteractions(emailSqsClient);
        verify(auditService).submitAuditEvent(AUTH_EMAIL_INVALID_CODE_REQUEST, auditContext);
    }

    @Test
    void checkEmailInvalidCodeRequestAuditEventStillEmittedWhenTICFHeaderNotProvided() {
        maxOutCodeRequestCount(VERIFY_EMAIL, JourneyType.REGISTRATION);
        usingValidSession();

        var body =
                format(
                        "{ \"email\": \"%s\", \"notificationType\": \"%s\", \"journeyType\": \"%s\" }",
                        EMAIL, VERIFY_EMAIL, JourneyType.REGISTRATION);
        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS_WITHOUT_AUDIT_ENCODED, body);

        var result = handler.handleRequest(event, context);

        assertEquals(400, result.getStatusCode());
        verify(auditService)
                .submitAuditEvent(
                        AUTH_EMAIL_INVALID_CODE_REQUEST,
                        auditContext.withTxmaAuditEncoded(Optional.empty()));
    }

    @Test
    void shouldReturn400IfUserHasReachedTheAccountRecoveryEmailOtpRequestLimit() {
        maxOutCodeRequestCount(VERIFY_CHANGE_HOW_GET_SECURITY_CODES, JourneyType.ACCOUNT_RECOVERY);
        usingValidSession();

        var body =
                format(
                        "{ \"email\": \"%s\", \"notificationType\": \"%s\", \"journeyType\": \"%s\" }",
                        EMAIL, VERIFY_CHANGE_HOW_GET_SECURITY_CODES, JourneyType.ACCOUNT_RECOVERY);
        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, body);

        var result = handler.handleRequest(event, context);

        assertEquals(400, result.getStatusCode());
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1046));
        verify(codeStorageService)
                .saveBlockedForEmail(
                        EMAIL,
                        CODE_REQUEST_BLOCKED_KEY_PREFIX + CodeRequestType.EMAIL_ACCOUNT_RECOVERY,
                        LOCKOUT_DURATION);
        verify(codeStorageService, never())
                .saveOtpCode(
                        EMAIL,
                        TEST_SIX_DIGIT_CODE,
                        CODE_EXPIRY_TIME,
                        VERIFY_CHANGE_HOW_GET_SECURITY_CODES);
        verifyNoInteractions(emailSqsClient);
        verify(auditService)
                .submitAuditEvent(AUTH_ACCOUNT_RECOVERY_EMAIL_INVALID_CODE_REQUEST, auditContext);
    }

    @Test
    void shouldReturn400IfUserHasReachedThePhoneCodeRequestLimit() {
        maxOutCodeRequestCount(VERIFY_PHONE_NUMBER, JourneyType.REGISTRATION);
        usingValidSession();

        var body =
                format(
                        "{ \"email\": \"%s\", \"notificationType\": \"%s\",  \"phoneNumber\": \"%s\", \"journeyType\": \"%s\"  }",
                        EMAIL,
                        VERIFY_PHONE_NUMBER,
                        CommonTestVariables.UK_MOBILE_NUMBER,
                        JourneyType.REGISTRATION);
        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, body);

        var result = handler.handleRequest(event, context);

        assertEquals(400, result.getStatusCode());
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1030));
        verify(codeStorageService)
                .saveBlockedForEmail(
                        EMAIL,
                        CODE_REQUEST_BLOCKED_KEY_PREFIX + CodeRequestType.SMS_REGISTRATION,
                        LOCKOUT_DURATION);
        verify(codeStorageService, never())
                .saveOtpCode(EMAIL, TEST_SIX_DIGIT_CODE, CODE_EXPIRY_TIME, VERIFY_PHONE_NUMBER);
        verifyNoInteractions(emailSqsClient);
        verify(auditService)
                .submitAuditEvent(
                        AUTH_PHONE_INVALID_CODE_REQUEST,
                        auditContext.withPhoneNumber(UK_MOBILE_NUMBER));
    }

    @Test
    void shouldReturn400IfUserIsBlockedFromRequestingAnyMoreRegistrationEmailOtps() {
        when(codeStorageService.isBlockedForEmail(
                        EMAIL,
                        CODE_REQUEST_BLOCKED_KEY_PREFIX + CodeRequestType.EMAIL_REGISTRATION))
                .thenReturn(true);
        usingValidSession();

        var body =
                format(
                        "{ \"email\": \"%s\", \"notificationType\": \"%s\", \"journeyType\": \"%s\" }",
                        EMAIL, VERIFY_EMAIL, JourneyType.REGISTRATION);
        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, body);

        var result = handler.handleRequest(event, context);

        assertEquals(400, result.getStatusCode());
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1031));
        verifyNoInteractions(emailSqsClient);
        verify(auditService).submitAuditEvent(AUTH_EMAIL_INVALID_CODE_REQUEST, auditContext);
    }

    @Test
    void shouldReturn400IfUserIsBlockedFromRequestingAnyMoreAccountRecoveryEmailOtps() {
        when(codeStorageService.isBlockedForEmail(
                        EMAIL,
                        CODE_REQUEST_BLOCKED_KEY_PREFIX + CodeRequestType.EMAIL_ACCOUNT_RECOVERY))
                .thenReturn(true);
        usingValidSession();

        var body =
                format(
                        "{ \"email\": \"%s\", \"notificationType\": \"%s\", \"journeyType\": \"%s\" }",
                        EMAIL, VERIFY_CHANGE_HOW_GET_SECURITY_CODES, JourneyType.ACCOUNT_RECOVERY);
        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, body);

        var result = handler.handleRequest(event, context);

        assertEquals(400, result.getStatusCode());
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1047));
        verifyNoInteractions(emailSqsClient);
        verify(auditService)
                .submitAuditEvent(AUTH_ACCOUNT_RECOVERY_EMAIL_INVALID_CODE_REQUEST, auditContext);
    }

    @Test
    void shouldReturn400IfUserIsBlockedFromRequestingAnyMorePhoneOtpCodes() {
        when(codeStorageService.isBlockedForEmail(
                        EMAIL, CODE_REQUEST_BLOCKED_KEY_PREFIX + CodeRequestType.SMS_REGISTRATION))
                .thenReturn(true);
        usingValidSession();

        var body =
                format(
                        "{ \"email\": \"%s\", \"notificationType\": \"%s\",  \"phoneNumber\": \"%s\", \"journeyType\": \"%s\"  }",
                        EMAIL,
                        VERIFY_PHONE_NUMBER,
                        CommonTestVariables.UK_MOBILE_NUMBER,
                        JourneyType.REGISTRATION);
        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, body);

        var result = handler.handleRequest(event, context);

        assertEquals(400, result.getStatusCode());
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1032));

        verifyNoInteractions(emailSqsClient);
        verify(auditService)
                .submitAuditEvent(
                        AUTH_PHONE_INVALID_CODE_REQUEST,
                        auditContext.withPhoneNumber(UK_MOBILE_NUMBER));
    }

    @Test
    void shouldReturn400IfUserIsBlockedFromEnteringRegistrationEmailOtpCodes() {
        usingValidSession();
        when(codeStorageService.isBlockedForEmail(
                        EMAIL, CODE_BLOCKED_KEY_PREFIX + CodeRequestType.EMAIL_REGISTRATION))
                .thenReturn(true);

        var body =
                format(
                        "{ \"email\": \"%s\", \"notificationType\": \"%s\", \"journeyType\": \"%s\" }",
                        EMAIL, VERIFY_EMAIL, JourneyType.REGISTRATION);
        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, body);

        var result = handler.handleRequest(event, context);

        assertEquals(400, result.getStatusCode());
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1033));
        verifyNoInteractions(emailSqsClient);
        verify(auditService).submitAuditEvent(AUTH_EMAIL_INVALID_CODE_REQUEST, auditContext);
    }

    @Test
    void shouldReturn400IfUserIsBlockedFromEnteringAccountRecoveryEmailOtpCodes() {
        usingValidSession();
        when(codeStorageService.isBlockedForEmail(
                        EMAIL, CODE_BLOCKED_KEY_PREFIX + CodeRequestType.EMAIL_ACCOUNT_RECOVERY))
                .thenReturn(true);

        var body =
                format(
                        "{ \"email\": \"%s\", \"notificationType\": \"%s\", \"journeyType\": \"%s\" }",
                        EMAIL, VERIFY_CHANGE_HOW_GET_SECURITY_CODES, JourneyType.ACCOUNT_RECOVERY);
        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, body);

        var result = handler.handleRequest(event, context);

        assertEquals(400, result.getStatusCode());
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1048));
        verifyNoInteractions(emailSqsClient);
        verify(auditService)
                .submitAuditEvent(AUTH_ACCOUNT_RECOVERY_EMAIL_INVALID_CODE_REQUEST, auditContext);
    }

    @Test
    void shouldReturn400IfUserIsBlockedFromEnteringPhoneOtpCodes() {
        when(codeStorageService.isBlockedForEmail(
                        EMAIL, CODE_BLOCKED_KEY_PREFIX + CodeRequestType.SMS_REGISTRATION))
                .thenReturn(true);
        usingValidSession();

        var body =
                format(
                        "{ \"email\": \"%s\", \"notificationType\": \"%s\", \"journeyType\": \"%s\" }",
                        EMAIL, VERIFY_PHONE_NUMBER, JourneyType.REGISTRATION);
        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, body);

        var result = handler.handleRequest(event, context);

        assertEquals(400, result.getStatusCode());
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1034));
        verifyNoInteractions(emailSqsClient);
        verify(auditService).submitAuditEvent(AUTH_PHONE_INVALID_CODE_REQUEST, auditContext);
    }

    @ParameterizedTest
    @EnumSource(
            value = NotificationType.class,
            names = {"ACCOUNT_CREATED_CONFIRMATION", "CHANGE_HOW_GET_SECURITY_CODES_CONFIRMATION"})
    void shouldReturn204WhenSendingAccountCreationEmail(NotificationType notificationType)
            throws Json.JsonException {
        usingValidSession();
        var event = new APIGatewayProxyRequestEvent();
        event.setHeaders(
                Map.of(SESSION_ID_HEADER, SESSION_ID, CLIENT_SESSION_ID_HEADER, CLIENT_SESSION_ID));
        event.setBody(
                format(
                        "{ \"email\": \"%s\", \"notificationType\": \"%s\", \"journeyType\": \"%s\" }",
                        EMAIL, notificationType, JourneyType.REGISTRATION));
        var result = handler.handleRequest(event, context);

        var notifyRequest =
                new NotifyRequest(
                        EMAIL,
                        notificationType,
                        SupportedLanguage.EN,
                        SESSION_ID,
                        CLIENT_SESSION_ID);
        verify(emailSqsClient)
                .send(
                        argThat(
                                partiallyContainsJsonString(
                                        objectMapper.writeValueAsString(notifyRequest),
                                        "unique_notification_reference")));
        verifyNoInteractions(codeStorageService);
        verifyNoInteractions(auditService);

        assertEquals(204, result.getStatusCode());
    }

    @ParameterizedTest
    @EnumSource(
            value = NotificationType.class,
            names = {"ACCOUNT_CREATED_CONFIRMATION", "CHANGE_HOW_GET_SECURITY_CODES_CONFIRMATION"})
    void shouldReturn204AndNotSendAccountCreationEmailForTestClientAndTestUser(
            NotificationType notificationType) {
        usingValidSession(TEST_CLIENT_ID);
        when(configurationService.isTestClientsEnabled()).thenReturn(true);

        var body =
                format(
                        "{ \"email\": \"%s\", \"notificationType\": \"%s\", \"journeyType\": \"%s\" }",
                        EMAIL, notificationType, JourneyType.REGISTRATION);
        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, body);

        var result = handler.handleRequest(event, context);

        assertEquals(204, result.getStatusCode());
        verifyNoInteractions(emailSqsClient);
        verifyNoInteractions(auditService);
    }

    private void maxOutCodeRequestCount(
            NotificationType notificationType, JourneyType journeyType) {
        authSession.resetCodeRequestCount(notificationType, journeyType);
        authSession.incrementCodeRequestCount(notificationType, journeyType);
        authSession.incrementCodeRequestCount(notificationType, journeyType);
        authSession.incrementCodeRequestCount(notificationType, journeyType);
        authSession.incrementCodeRequestCount(notificationType, journeyType);
        authSession.incrementCodeRequestCount(notificationType, journeyType);
    }

    private void usingValidSession() {
        usingValidSession(CLIENT_ID);
    }

    private void usingValidSession(String clientId) {
        when(authSessionService.getSessionFromRequestHeaders(anyMap()))
                .thenReturn(Optional.of(authSession.withClientId(clientId)));
    }
}
