package uk.gov.di.accountmanagement.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import software.amazon.awssdk.core.exception.SdkClientException;
import uk.gov.di.accountmanagement.domain.AccountManagementAuditableEvent;
import uk.gov.di.accountmanagement.entity.NotificationType;
import uk.gov.di.accountmanagement.entity.NotifyRequest;
import uk.gov.di.accountmanagement.helpers.AuditHelper;
import uk.gov.di.accountmanagement.services.AwsSqsClient;
import uk.gov.di.accountmanagement.services.CodeStorageService;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.shared.domain.RequestHeaders;
import uk.gov.di.authentication.shared.entity.EmailCheckResultStore;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.PriorityIdentifier;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethod;
import uk.gov.di.authentication.shared.helpers.ClientSessionIdHelper;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.helpers.LocaleHelper.SupportedLanguage;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.helpers.SaltHelper;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;
import uk.gov.di.authentication.shared.services.CodeGeneratorService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoEmailCheckResultService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.SerializationService;
import uk.gov.di.authentication.shared.services.mfa.MFAMethodsService;
import uk.gov.di.authentication.shared.services.mfa.MfaRetrieveFailureReason;

import java.util.ArrayList;
import java.util.Date;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Stream;

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.di.accountmanagement.entity.NotificationType.VERIFY_EMAIL;
import static uk.gov.di.accountmanagement.entity.NotificationType.VERIFY_PHONE_NUMBER;
import static uk.gov.di.authentication.shared.entity.ErrorResponse.ERROR_1004;
import static uk.gov.di.authentication.shared.services.AuditService.MetadataPair.pair;
import static uk.gov.di.authentication.sharedtest.helper.RequestEventHelper.contextWithSourceIp;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;

class SendOtpNotificationHandlerTest {

    private static final String TEST_EMAIL_ADDRESS = "joe.bloggs@digital.cabinet-office.gov.uk";
    private static final String TEST_TEST_USER_EMAIL_ADDRESS =
            "tester.joe.bloggs@digital.cabinet-office.gov.uk";
    private static final String TEST_CLIENT_ID = "tester-client-id";
    private static final String SESSION_ID = "some-client-session-id";
    private static final String TEST_SIX_DIGIT_CODE = "123456";
    private static final String TEST_CLIENT_AND_USER_SIX_DIGIT_CODE = "654321";
    private static final String TEST_PHONE_NUMBER = "07755551084";
    private static final String TXMA_ENCODED_HEADER_VALUE = "txma-test-value";
    private static final long CODE_EXPIRY_TIME = 900;
    private static final byte[] SALT = SaltHelper.generateNewSalt();
    private static final Subject INTERNAL_SUBJECT = new Subject();
    private final String expectedCommonSubject =
            ClientSubjectHelper.calculatePairwiseIdentifier(
                    INTERNAL_SUBJECT.getValue(), "test.account.gov.uk", SALT);
    private final Json objectMapper = SerializationService.getInstance();

    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final AwsSqsClient emailSqsClient = mock(AwsSqsClient.class);
    private final AwsSqsClient pendingEmailCheckSqsClient = mock(AwsSqsClient.class);
    private final CodeGeneratorService codeGeneratorService = mock(CodeGeneratorService.class);
    private final CodeStorageService codeStorageService = mock(CodeStorageService.class);
    private final DynamoService dynamoService = mock(DynamoService.class);
    private final CloudwatchMetricsService cloudwatchMetricsService =
            mock(CloudwatchMetricsService.class);
    private final DynamoEmailCheckResultService dynamoEmailCheckResultService =
            mock(DynamoEmailCheckResultService.class);
    private final ClientService clientService = mock(ClientService.class);
    private final AuditService auditService = mock(AuditService.class);
    private final MFAMethodsService mfaMethodsService = mock(MFAMethodsService.class);

    private final Context context = mock(Context.class);
    private static final String PERSISTENT_ID = "some-persistent-session-id";

    private final AuditContext auditContext =
            new AuditContext(
                    TEST_CLIENT_ID,
                    SESSION_ID,
                    AuditService.UNKNOWN,
                    expectedCommonSubject,
                    TEST_EMAIL_ADDRESS,
                    "123.123.123.123",
                    TEST_PHONE_NUMBER,
                    PERSISTENT_ID,
                    Optional.of(TXMA_ENCODED_HEADER_VALUE));
    private APIGatewayProxyRequestEvent.ProxyRequestContext eventContext;

    private final SendOtpNotificationHandler handler =
            new SendOtpNotificationHandler(
                    configurationService,
                    emailSqsClient,
                    pendingEmailCheckSqsClient,
                    codeGeneratorService,
                    codeStorageService,
                    dynamoService,
                    dynamoEmailCheckResultService,
                    auditService,
                    clientService,
                    cloudwatchMetricsService,
                    mfaMethodsService);

    @BeforeEach
    void setup() {
        when(configurationService.getDefaultOtpCodeExpiry()).thenReturn(CODE_EXPIRY_TIME);
        when(configurationService.isEmailCheckEnabled()).thenReturn(true);
        when(codeGeneratorService.sixDigitCode()).thenReturn(TEST_SIX_DIGIT_CODE);
        when(configurationService.getTestClientVerifyEmailOTP())
                .thenReturn(Optional.of(TEST_CLIENT_AND_USER_SIX_DIGIT_CODE));
        when(configurationService.getEnvironment()).thenReturn("test-env");
        when(configurationService.getTestClientVerifyPhoneNumberOTP())
                .thenReturn(Optional.of(TEST_CLIENT_AND_USER_SIX_DIGIT_CODE));
        when(configurationService.getAwsRegion()).thenReturn("eu-west-2");

        when(clientService.isTestJourney(TEST_CLIENT_ID, TEST_TEST_USER_EMAIL_ADDRESS))
                .thenReturn(true);

        eventContext = contextWithSourceIp("123.123.123.123");
        Map<String, Object> authorizer =
                Map.of("clientId", TEST_CLIENT_ID, "principalId", expectedCommonSubject);
        eventContext.setAuthorizer(authorizer);
    }

    @Test
    void shouldReturn204AndPutMessageOnQueueForAValidEmailRequest() throws Json.JsonException {
        var mfaMethods = new ArrayList<MFAMethod>();
        var mfaMethod =
                MFAMethod.smsMfaMethod(
                        true,
                        true,
                        TEST_PHONE_NUMBER,
                        PriorityIdentifier.DEFAULT,
                        UUID.randomUUID().toString());
        mfaMethods.add(mfaMethod);

        when(mfaMethodsService.getMfaMethods(TEST_EMAIL_ADDRESS))
                .thenReturn(new Result.Success<>(mfaMethods));

        NotifyRequest notifyRequest =
                new NotifyRequest(
                        TEST_EMAIL_ADDRESS,
                        VERIFY_EMAIL,
                        TEST_SIX_DIGIT_CODE,
                        SupportedLanguage.EN,
                        false,
                        TEST_EMAIL_ADDRESS);
        String serialisedRequest = objectMapper.writeValueAsString(notifyRequest);

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(
                Map.of(
                        PersistentIdHelper.PERSISTENT_ID_HEADER_NAME,
                        PERSISTENT_ID,
                        RequestHeaders.SESSION_ID_HEADER,
                        "some-session-id",
                        RequestHeaders.CLIENT_SESSION_ID_HEADER,
                        "some-client-session-id",
                        AuditHelper.TXMA_ENCODED_HEADER_NAME,
                        TXMA_ENCODED_HEADER_VALUE));
        event.setRequestContext(eventContext);
        event.setBody(
                format(
                        "{ \"email\": \"%s\", \"notificationType\": \"%s\" }",
                        TEST_EMAIL_ADDRESS, VERIFY_EMAIL));

        Date mockedDate = new Date();
        UUID mockedUUID = UUID.fromString("5fc03087-d265-11e7-b8c6-83e29cd24f4c");
        try (MockedStatic<NowHelper> mockedNowHelperClass = Mockito.mockStatic(NowHelper.class);
                MockedStatic<UUID> mockedUUIDClass = Mockito.mockStatic(UUID.class)) {
            mockedNowHelperClass.when(NowHelper::now).thenReturn(mockedDate);
            mockedUUIDClass.when(UUID::randomUUID).thenReturn(mockedUUID);

            APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);
            assertEquals(204, result.getStatusCode());

            verify(emailSqsClient).send(serialisedRequest);
            verify(codeStorageService)
                    .saveOtpCode(
                            TEST_EMAIL_ADDRESS,
                            TEST_SIX_DIGIT_CODE,
                            CODE_EXPIRY_TIME,
                            VERIFY_EMAIL);

            verify(auditService)
                    .submitAuditEvent(
                            AccountManagementAuditableEvent.AUTH_SEND_OTP,
                            auditContext.withPhoneNumber(null),
                            pair("notification-type", VERIFY_EMAIL),
                            pair("test-user", false));
            verify(cloudwatchMetricsService)
                    .incrementCounter(eq("UserSubmittedCredential"), anyMap());
        }
    }

    private static Stream<Arguments> requestEmailCheckPermutations() {
        return Stream.of(Arguments.of(true, false), Arguments.of(false, true));
    }

    @ParameterizedTest
    @MethodSource("requestEmailCheckPermutations")
    void shouldCorrectlyRequestEmailCheck(
            boolean cachedResultAlreadyExists, boolean expectedCheckRequested) {
        var mfaMethods = new ArrayList<MFAMethod>();
        var mfaMethod =
                MFAMethod.smsMfaMethod(
                        true,
                        true,
                        TEST_PHONE_NUMBER,
                        PriorityIdentifier.DEFAULT,
                        UUID.randomUUID().toString());
        mfaMethods.add(mfaMethod);

        when(mfaMethodsService.getMfaMethods(TEST_EMAIL_ADDRESS))
                .thenReturn(new Result.Success<>(mfaMethods));

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(
                Map.of(
                        PersistentIdHelper.PERSISTENT_ID_HEADER_NAME,
                        PERSISTENT_ID,
                        RequestHeaders.SESSION_ID_HEADER,
                        "some-session-id",
                        RequestHeaders.CLIENT_SESSION_ID_HEADER,
                        "some-client-session-id",
                        AuditHelper.TXMA_ENCODED_HEADER_NAME,
                        TXMA_ENCODED_HEADER_VALUE));
        event.setRequestContext(eventContext);
        event.setBody(
                format(
                        "{ \"email\": \"%s\", \"notificationType\": \"%s\" }",
                        TEST_EMAIL_ADDRESS, VERIFY_EMAIL));

        if (cachedResultAlreadyExists) {
            when(dynamoEmailCheckResultService.getEmailCheckStore(TEST_EMAIL_ADDRESS))
                    .thenReturn(
                            Optional.of(new EmailCheckResultStore().withEmail(TEST_EMAIL_ADDRESS)));
        }

        Date mockedDate = new Date();
        UUID mockedUUID = UUID.fromString("5fc03087-d265-11e7-b8c6-83e29cd24f4c");
        try (MockedStatic<NowHelper> mockedNowHelperClass = Mockito.mockStatic(NowHelper.class)) {
            try (MockedStatic<UUID> mockedUUIDClass = Mockito.mockStatic(UUID.class)) {
                mockedNowHelperClass.when(NowHelper::now).thenReturn(mockedDate);
                mockedUUIDClass.when(UUID::randomUUID).thenReturn(mockedUUID);

                handler.handleRequest(event, context);

                if (expectedCheckRequested) {
                    verify(pendingEmailCheckSqsClient)
                            .send(
                                    format(
                                            "{\"userId\":\"%s\",\"requestReference\":\"%s\",\"emailAddress\":\"%s\",\"userSessionId\":\"%s\",\"govukSigninJourneyId\":\"%s\",\"persistentSessionId\":\"%s\",\"ipAddress\":\"%s\",\"journeyType\":\"%s\",\"timeOfInitialRequest\":%d,\"isTestUserRequest\":%b}",
                                            expectedCommonSubject,
                                            mockedUUID,
                                            TEST_EMAIL_ADDRESS,
                                            "some-session-id",
                                            "some-client-session-id",
                                            "some-persistent-session-id",
                                            "123.123.123.123",
                                            JourneyType.ACCOUNT_MANAGEMENT,
                                            mockedDate.toInstant().toEpochMilli(),
                                            false));
                } else {
                    verifyNoInteractions(pendingEmailCheckSqsClient);
                }
            }
        }
    }

    @Test
    void shouldReturn204AndNotEnqueuePendingEmailCheckWhenFeatureFlagDisabled()
            throws Json.JsonException {
        var mfaMethods = new ArrayList<MFAMethod>();
        var mfaMethod =
                MFAMethod.smsMfaMethod(
                        true,
                        true,
                        TEST_PHONE_NUMBER,
                        PriorityIdentifier.DEFAULT,
                        UUID.randomUUID().toString());
        mfaMethods.add(mfaMethod);

        when(mfaMethodsService.getMfaMethods(TEST_EMAIL_ADDRESS))
                .thenReturn(new Result.Success<>(mfaMethods));

        when(configurationService.isEmailCheckEnabled()).thenReturn(false);

        String persistentIdValue = "some-persistent-session-id";
        NotifyRequest notifyRequest =
                new NotifyRequest(
                        TEST_EMAIL_ADDRESS,
                        VERIFY_EMAIL,
                        TEST_SIX_DIGIT_CODE,
                        SupportedLanguage.EN,
                        false,
                        null);
        String serialisedRequest = objectMapper.writeValueAsString(notifyRequest);

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(
                Map.of(
                        PersistentIdHelper.PERSISTENT_ID_HEADER_NAME,
                        persistentIdValue,
                        RequestHeaders.SESSION_ID_HEADER,
                        "some-session-id",
                        RequestHeaders.CLIENT_SESSION_ID_HEADER,
                        "some-client-session-id",
                        AuditHelper.TXMA_ENCODED_HEADER_NAME,
                        TXMA_ENCODED_HEADER_VALUE));
        event.setRequestContext(eventContext);
        event.setBody(
                format(
                        "{ \"email\": \"%s\", \"notificationType\": \"%s\" }",
                        TEST_EMAIL_ADDRESS, VERIFY_EMAIL));

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);
        assertEquals(204, result.getStatusCode());

        verifyNoInteractions(pendingEmailCheckSqsClient);
    }

    @Test
    void shouldReturn204AndPutMessageOnQueueForAValidPhoneRequest() throws Json.JsonException {
        var mfaMethods = new ArrayList<MFAMethod>();
        var mfaMethod =
                MFAMethod.smsMfaMethod(
                        true,
                        true,
                        TEST_PHONE_NUMBER,
                        PriorityIdentifier.DEFAULT,
                        UUID.randomUUID().toString());
        mfaMethods.add(mfaMethod);

        when(mfaMethodsService.getMfaMethods(TEST_EMAIL_ADDRESS))
                .thenReturn(new Result.Success<>(mfaMethods));

        NotifyRequest notifyRequest =
                new NotifyRequest(
                        TEST_PHONE_NUMBER,
                        VERIFY_PHONE_NUMBER,
                        TEST_SIX_DIGIT_CODE,
                        SupportedLanguage.EN,
                        false,
                        TEST_EMAIL_ADDRESS);

        String serialisedRequest = objectMapper.writeValueAsString(notifyRequest);

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(
                Map.of(
                        PersistentIdHelper.PERSISTENT_ID_HEADER_NAME,
                        PERSISTENT_ID,
                        ClientSessionIdHelper.SESSION_ID_HEADER_NAME,
                        SESSION_ID,
                        AuditHelper.TXMA_ENCODED_HEADER_NAME,
                        TXMA_ENCODED_HEADER_VALUE));
        event.setRequestContext(eventContext);
        event.setBody(
                format(
                        "{ \"email\": \"%s\", \"notificationType\": \"%s\", \"phoneNumber\": \"%s\"  }",
                        TEST_EMAIL_ADDRESS, VERIFY_PHONE_NUMBER, TEST_PHONE_NUMBER));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertEquals(204, result.getStatusCode());

        verify(emailSqsClient).send(serialisedRequest);
        verify(codeStorageService)
                .saveOtpCode(
                        TEST_EMAIL_ADDRESS,
                        TEST_SIX_DIGIT_CODE,
                        CODE_EXPIRY_TIME,
                        VERIFY_PHONE_NUMBER);

        verify(auditService)
                .submitAuditEvent(
                        AccountManagementAuditableEvent.AUTH_SEND_OTP,
                        auditContext,
                        pair("notification-type", VERIFY_PHONE_NUMBER),
                        pair("test-user", false));
        verify(cloudwatchMetricsService).incrementCounter(eq("UserSubmittedCredential"), anyMap());
    }

    @Disabled
    @Test
    void shouldReturn204AndNotPutMessageOnQueueForAValidEmailRequestFromTestUser() {
        when(configurationService.isTestClientsEnabled()).thenReturn(true);

        String persistentIdValue = "some-persistent-session-id";

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(
                Map.of(
                        PersistentIdHelper.PERSISTENT_ID_HEADER_NAME,
                        persistentIdValue,
                        ClientSessionIdHelper.SESSION_ID_HEADER_NAME,
                        SESSION_ID,
                        AuditHelper.TXMA_ENCODED_HEADER_NAME,
                        TXMA_ENCODED_HEADER_VALUE));
        event.setRequestContext(eventContext);
        event.setBody(
                format(
                        "{ \"email\": \"%s\", \"notificationType\": \"%s\" }",
                        TEST_TEST_USER_EMAIL_ADDRESS, VERIFY_EMAIL));

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertEquals(204, result.getStatusCode());

        verifyNoInteractions(emailSqsClient);
        verify(codeStorageService)
                .saveOtpCode(
                        TEST_TEST_USER_EMAIL_ADDRESS,
                        TEST_CLIENT_AND_USER_SIX_DIGIT_CODE,
                        CODE_EXPIRY_TIME,
                        VERIFY_EMAIL);

        verify(auditService)
                .submitAuditEvent(
                        AccountManagementAuditableEvent.AUTH_SEND_OTP,
                        auditContext.withPhoneNumber(null).withEmail(TEST_TEST_USER_EMAIL_ADDRESS),
                        pair("notification-type", VERIFY_EMAIL),
                        pair("test-user", true));
    }

    @Nested
    class ServerErrors {
        @Test
        void shouldReturn500WhenClientIdNotAvailable() {
            when(configurationService.isTestClientsEnabled()).thenReturn(false);
            String persistentIdValue = "some-persistent-session-id";

            APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
            event.setHeaders(
                    Map.of(
                            PersistentIdHelper.PERSISTENT_ID_HEADER_NAME,
                            persistentIdValue,
                            AuditHelper.TXMA_ENCODED_HEADER_NAME,
                            TXMA_ENCODED_HEADER_VALUE));
            event.setRequestContext(eventContext);
            event.setBody(
                    format(
                            "{ \"email\": \"%s\", \"notificationType\": \"%s\" }",
                            TEST_TEST_USER_EMAIL_ADDRESS, VERIFY_EMAIL));
            event.setRequestContext(null);

            APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

            assertEquals(500, result.getStatusCode());

            verifyNoInteractions(emailSqsClient, codeStorageService, auditService);
        }

        @Test
        void shouldReturn500WhenUnexpectedException() {
            when(configurationService.isTestClientsEnabled()).thenReturn(false);

            Mockito.reset(clientService);

            when(clientService.isTestJourney(TEST_CLIENT_ID, TEST_TEST_USER_EMAIL_ADDRESS))
                    .thenThrow(new RuntimeException("unexpected"));

            String persistentIdValue = "some-persistent-session-id";

            APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
            event.setHeaders(
                    Map.of(
                            PersistentIdHelper.PERSISTENT_ID_HEADER_NAME,
                            persistentIdValue,
                            AuditHelper.TXMA_ENCODED_HEADER_NAME,
                            TXMA_ENCODED_HEADER_VALUE));
            event.setRequestContext(eventContext);
            event.setBody(
                    format(
                            "{ \"email\": \"%s\", \"notificationType\": \"%s\" }",
                            TEST_TEST_USER_EMAIL_ADDRESS, VERIFY_EMAIL));

            APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

            assertEquals(500, result.getStatusCode());

            verifyNoInteractions(emailSqsClient, codeStorageService, auditService);
        }

        @Test
        void shouldReturn500OnRequestFromTestUserIfTestClientsNotEnabled() {
            when(configurationService.isTestClientsEnabled()).thenReturn(false);
            String persistentIdValue = "some-persistent-session-id";

            APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
            event.setHeaders(
                    Map.of(
                            PersistentIdHelper.PERSISTENT_ID_HEADER_NAME,
                            persistentIdValue,
                            AuditHelper.TXMA_ENCODED_HEADER_NAME,
                            TXMA_ENCODED_HEADER_VALUE));
            event.setRequestContext(eventContext);
            event.setBody(
                    format(
                            "{ \"email\": \"%s\", \"notificationType\": \"%s\" }",
                            TEST_TEST_USER_EMAIL_ADDRESS, VERIFY_EMAIL));

            APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

            assertEquals(500, result.getStatusCode());

            verifyNoInteractions(emailSqsClient, codeStorageService, auditService);
        }

        @Test
        void shouldReturn500IfMessageCannotBeSentToQueue() throws Json.JsonException {
            var mfaMethods = new ArrayList<MFAMethod>();
            var defaultMfaMethod =
                    MFAMethod.smsMfaMethod(
                            true,
                            true,
                            "+447755551084",
                            PriorityIdentifier.DEFAULT,
                            UUID.randomUUID().toString());

            mfaMethods.add(defaultMfaMethod);

            when(mfaMethodsService.getMfaMethods(TEST_EMAIL_ADDRESS))
                    .thenReturn(new Result.Success<>(mfaMethods));

            NotifyRequest notifyRequest =
                    new NotifyRequest(
                            TEST_EMAIL_ADDRESS,
                            VERIFY_EMAIL,
                            TEST_SIX_DIGIT_CODE,
                            SupportedLanguage.EN,
                            false,
                            TEST_EMAIL_ADDRESS);
            String serialisedRequest = objectMapper.writeValueAsString(notifyRequest);
            doThrow(SdkClientException.class).when(emailSqsClient).send(serialisedRequest);

            APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
            event.setHeaders(Map.of());
            event.setRequestContext(eventContext);
            event.setBody(
                    format(
                            "{ \"email\": \"%s\", \"notificationType\": \"%s\" }",
                            TEST_EMAIL_ADDRESS, VERIFY_EMAIL));
            APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

            assertEquals(500, result.getStatusCode());
            assertTrue(result.getBody().contains("Error sending message to queue"));

            verifyNoInteractions(auditService);
        }
    }

    @Nested
    class ClientErrors {

        @Nested
        class MigratedUsers {
            @Test
            void shouldReturn400IfRequestIsMissingEmail() {
                APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
                event.setHeaders(Map.of());
                event.setBody("{ }");
                event.setRequestContext(eventContext);
                APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

                assertEquals(400, result.getStatusCode());
                assertThat(result, hasJsonBody(ErrorResponse.ERROR_1001));

                verifyNoInteractions(auditService);
            }

            @Test
            void shouldReturn400IfEmailAddressIsInvalid() {
                APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
                event.setHeaders(Map.of());
                event.setRequestContext(eventContext);
                event.setBody(
                        format(
                                "{ \"email\": \"%s\", \"notificationType\": \"%s\" }",
                                "not.an.email", VERIFY_EMAIL));

                APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

                assertEquals(400, result.getStatusCode());
                assertThat(result, hasJsonBody(ERROR_1004));

                verifyNoInteractions(auditService);
            }

            @Test
            void shouldReturn400IfPhoneNumberIsInvalid() {
                var mfaMethods = new ArrayList<MFAMethod>();
                var defaultMfaMethod =
                        MFAMethod.smsMfaMethod(
                                true,
                                true,
                                "+447755551084",
                                PriorityIdentifier.DEFAULT,
                                UUID.randomUUID().toString());

                mfaMethods.add(defaultMfaMethod);

                when(mfaMethodsService.getMfaMethods(TEST_EMAIL_ADDRESS))
                        .thenReturn(new Result.Success<>(mfaMethods));

                APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
                event.setHeaders(Map.of());
                event.setRequestContext(eventContext);
                event.setBody(
                        format(
                                "{ \"email\": \"%s\", \"notificationType\": \"%s\", \"phoneNumber\": \"%s\" }",
                                TEST_EMAIL_ADDRESS, VERIFY_PHONE_NUMBER, "12345"));

                APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

                assertEquals(400, result.getStatusCode());
                assertThat(result, hasJsonBody(ErrorResponse.INVALID_PHONE_NUMBER));

                verifyNoInteractions(auditService);
            }

            @Test
            void shouldReturn400IfNewPhoneNumberIsTheSameAsCurrentPhoneNumber() {
                var mfaMethods = new ArrayList<MFAMethod>();
                var defaultMfaMethod =
                        MFAMethod.smsMfaMethod(
                                true,
                                true,
                                "+447755551084",
                                PriorityIdentifier.DEFAULT,
                                UUID.randomUUID().toString());

                mfaMethods.add(defaultMfaMethod);

                when(mfaMethodsService.getMfaMethods(TEST_EMAIL_ADDRESS))
                        .thenReturn(new Result.Success<>(mfaMethods));

                var event = new APIGatewayProxyRequestEvent();
                event.setHeaders(Map.of());
                event.setRequestContext(eventContext);
                event.setBody(
                        format(
                                "{ \"email\": \"%s\", \"notificationType\": \"%s\", \"phoneNumber\": \"%s\" }",
                                TEST_EMAIL_ADDRESS, VERIFY_PHONE_NUMBER, TEST_PHONE_NUMBER));

                var result = handler.handleRequest(event, context);

                assertEquals(400, result.getStatusCode());
                assertThat(result, hasJsonBody(ErrorResponse.NEW_PHONE_NUMBER_ALREADY_IN_USE));
                verifyNoInteractions(auditService);
            }

            @Test
            void shouldReturn400WhenUserProfileMissing() {
                when(mfaMethodsService.getMfaMethods(TEST_EMAIL_ADDRESS))
                        .thenReturn(
                                new Result.Failure<>(
                                        MfaRetrieveFailureReason.USER_DOES_NOT_HAVE_ACCOUNT));

                var event = new APIGatewayProxyRequestEvent();
                event.setHeaders(Map.of());
                event.setRequestContext(eventContext);
                event.setBody(
                        format(
                                "{ \"email\": \"%s\", \"notificationType\": \"%s\", \"phoneNumber\": \"%s\" }",
                                TEST_EMAIL_ADDRESS, VERIFY_PHONE_NUMBER, TEST_PHONE_NUMBER));

                var result = handler.handleRequest(event, context);

                assertEquals(400, result.getStatusCode());
                assertThat(result, hasJsonBody(ErrorResponse.USER_DOES_NOT_HAVE_ACCOUNT));
                verifyNoInteractions(auditService);
            }

            @Test
            void shouldReturn400WhenPhoneNumberInvalid() {
                var mfaMethods = new ArrayList<MFAMethod>();
                var defaultMfaMethod =
                        MFAMethod.smsMfaMethod(
                                true,
                                true,
                                "+447755551084",
                                PriorityIdentifier.DEFAULT,
                                UUID.randomUUID().toString());

                mfaMethods.add(defaultMfaMethod);

                when(mfaMethodsService.getMfaMethods(TEST_EMAIL_ADDRESS))
                        .thenReturn(new Result.Success<>(mfaMethods));

                var event = new APIGatewayProxyRequestEvent();
                event.setHeaders(Map.of());
                event.setRequestContext(eventContext);
                event.setBody(
                        format(
                                "{ \"email\": \"%s\", \"notificationType\": \"%s\", \"phoneNumber\": \"%s\" }",
                                TEST_EMAIL_ADDRESS, VERIFY_PHONE_NUMBER, "not-a phone number"));

                var result = handler.handleRequest(event, context);

                assertEquals(400, result.getStatusCode());
                assertThat(result, hasJsonBody(ErrorResponse.INVALID_PHONE_NUMBER));
                verifyNoInteractions(auditService);
            }

            @Test
            void shouldReturn400WhenInvalidNotificationType() {
                APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
                event.setHeaders(Map.of());
                event.setRequestContext(eventContext);
                event.setBody(
                        format(
                                "{ \"email\": \"%s\", \"notificationType\": \"%s\" }",
                                TEST_EMAIL_ADDRESS, "VERIFY_PASSWORD"));
                APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

                assertEquals(400, result.getStatusCode());
                assertThat(result, hasJsonBody(ErrorResponse.ERROR_1001));

                verify(emailSqsClient, never()).send(anyString());
                verify(codeStorageService, never())
                        .saveOtpCode(
                                anyString(), anyString(), anyLong(), any(NotificationType.class));

                verifyNoInteractions(auditService);
            }

            @Test
            void cannotChangeEmailToOneInUseByAnotherUser() {
                when(dynamoService.userExists(eq(TEST_EMAIL_ADDRESS))).thenReturn(true);

                var event = new APIGatewayProxyRequestEvent();
                event.setHeaders(Map.of());
                event.setRequestContext(eventContext);
                event.setBody(
                        format(
                                "{ \"email\": \"%s\", \"notificationType\": \"%s\" }",
                                TEST_EMAIL_ADDRESS, VERIFY_EMAIL));

                var result = handler.handleRequest(event, context);

                assertEquals(400, result.getStatusCode());
                assertThat(result, hasJsonBody(ErrorResponse.ERROR_1009));
                verifyNoInteractions(auditService);
            }
        }

        @Nested
        class UnMigratedUsers {
            @Test
            void shouldReturn400WhenNoUserCredentialsForEmail() {
                when(mfaMethodsService.getMfaMethods(TEST_EMAIL_ADDRESS))
                        .thenReturn(
                                new Result.Failure<>(
                                        MfaRetrieveFailureReason.USER_DOES_NOT_HAVE_ACCOUNT));

                var event = new APIGatewayProxyRequestEvent();
                event.setHeaders(Map.of());
                event.setRequestContext(eventContext);
                event.setBody(
                        format(
                                "{ \"email\": \"%s\", \"notificationType\": \"%s\", \"phoneNumber\": \"%s\" }",
                                TEST_EMAIL_ADDRESS, VERIFY_PHONE_NUMBER, TEST_PHONE_NUMBER));

                var result = handler.handleRequest(event, context);

                assertEquals(400, result.getStatusCode());
                assertThat(result, hasJsonBody(ErrorResponse.USER_DOES_NOT_HAVE_ACCOUNT));
                verifyNoInteractions(auditService);
            }

            @Test
            void shouldReturn400WhenPhoneNumberAlreadyInUse() {
                var mfaMethods = new ArrayList<MFAMethod>();
                var defaultMfaMethod =
                        MFAMethod.smsMfaMethod(
                                true,
                                true,
                                "+447755551084",
                                PriorityIdentifier.DEFAULT,
                                UUID.randomUUID().toString());

                mfaMethods.add(defaultMfaMethod);

                when(mfaMethodsService.getMfaMethods(TEST_EMAIL_ADDRESS))
                        .thenReturn(new Result.Success<>(mfaMethods));

                var event = new APIGatewayProxyRequestEvent();
                event.setHeaders(Map.of());
                event.setRequestContext(eventContext);
                event.setBody(
                        format(
                                "{ \"email\": \"%s\", \"notificationType\": \"%s\", \"phoneNumber\": \"%s\" }",
                                TEST_EMAIL_ADDRESS, VERIFY_PHONE_NUMBER, TEST_PHONE_NUMBER));

                var result = handler.handleRequest(event, context);

                assertEquals(400, result.getStatusCode());
                assertThat(result, hasJsonBody(ErrorResponse.NEW_PHONE_NUMBER_ALREADY_IN_USE));
                verifyNoInteractions(auditService);
            }

            @Test
            void shouldReturn400WhenPhoneNumberInvalid() {
                var mfaMethods = new ArrayList<MFAMethod>();
                var defaultMfaMethod =
                        MFAMethod.smsMfaMethod(
                                true,
                                true,
                                "+447755551084",
                                PriorityIdentifier.DEFAULT,
                                UUID.randomUUID().toString());

                mfaMethods.add(defaultMfaMethod);

                when(mfaMethodsService.getMfaMethods(TEST_EMAIL_ADDRESS))
                        .thenReturn(new Result.Success<>(mfaMethods));

                var event = new APIGatewayProxyRequestEvent();
                event.setHeaders(Map.of());
                event.setRequestContext(eventContext);
                event.setBody(
                        format(
                                "{ \"email\": \"%s\", \"notificationType\": \"%s\", \"phoneNumber\": \"%s\" }",
                                TEST_EMAIL_ADDRESS, VERIFY_PHONE_NUMBER, "not a phone-num"));

                var result = handler.handleRequest(event, context);

                assertEquals(400, result.getStatusCode());
                assertThat(result, hasJsonBody(ErrorResponse.INVALID_PHONE_NUMBER));
                verifyNoInteractions(auditService);
            }

            @Test
            void shouldReturn400WhenAccountAlreadyExistsWithGivenEmail() {
                when(dynamoService.userExists(eq(TEST_EMAIL_ADDRESS))).thenReturn(true);

                APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
                event.setHeaders(Map.of());
                event.setRequestContext(eventContext);
                event.setBody(
                        format(
                                "{ \"email\": \"%s\", \"notificationType\": \"%s\" }",
                                TEST_EMAIL_ADDRESS, VERIFY_EMAIL));
                APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

                assertEquals(400, result.getStatusCode());
                assertThat(result, hasJsonBody(ErrorResponse.ERROR_1009));

                verifyNoInteractions(auditService);
            }
        }
    }
}
