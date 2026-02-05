package uk.gov.di.accountmanagement.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.SQSEvent;
import com.amazonaws.services.lambda.runtime.events.SQSEvent.SQSMessage;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import uk.gov.di.accountmanagement.entity.NotificationType;
import uk.gov.di.accountmanagement.entity.NotifyRequest;
import uk.gov.di.authentication.shared.helpers.CommonTestVariables;
import uk.gov.di.authentication.shared.helpers.LocaleHelper.SupportedLanguage;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.InternationalSmsSendLimitService;
import uk.gov.di.authentication.shared.services.NotificationService;
import uk.gov.di.authentication.shared.services.SerializationService;
import uk.gov.di.authentication.sharedtest.logging.CaptureLoggingExtension;
import uk.gov.service.notify.NotificationClientException;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasItem;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.di.accountmanagement.entity.NotificationType.BACKUP_METHOD_ADDED;
import static uk.gov.di.accountmanagement.entity.NotificationType.BACKUP_METHOD_REMOVED;
import static uk.gov.di.accountmanagement.entity.NotificationType.CHANGED_AUTHENTICATOR_APP;
import static uk.gov.di.accountmanagement.entity.NotificationType.CHANGED_DEFAULT_MFA;
import static uk.gov.di.accountmanagement.entity.NotificationType.DELETE_ACCOUNT;
import static uk.gov.di.accountmanagement.entity.NotificationType.EMAIL_UPDATED;
import static uk.gov.di.accountmanagement.entity.NotificationType.PASSWORD_UPDATED;
import static uk.gov.di.accountmanagement.entity.NotificationType.PHONE_NUMBER_UPDATED;
import static uk.gov.di.accountmanagement.entity.NotificationType.SWITCHED_MFA_METHODS;
import static uk.gov.di.accountmanagement.entity.NotificationType.VERIFY_EMAIL;
import static uk.gov.di.accountmanagement.entity.NotificationType.VERIFY_PHONE_NUMBER;
import static uk.gov.di.accountmanagement.lambda.LogMessageTemplates.EMAIL_HAS_BEEN_SENT_USING_NOTIFY;
import static uk.gov.di.accountmanagement.lambda.LogMessageTemplates.ERROR_SENDING_WITH_NOTIFY;
import static uk.gov.di.accountmanagement.lambda.LogMessageTemplates.NOTIFY_TEST_DESTINATION_USED_WRITING_TO_S3_BUCKET;
import static uk.gov.di.accountmanagement.lambda.LogMessageTemplates.NOT_WRITING_TO_BUCKET_AS_NOT_OTP_NOTIFICATION;
import static uk.gov.di.accountmanagement.lambda.LogMessageTemplates.TEXT_HAS_BEEN_SENT_USING_NOTIFY;
import static uk.gov.di.accountmanagement.lambda.LogMessageTemplates.UNEXPECTED_ERROR_SENDING_NOTIFICATION;
import static uk.gov.di.accountmanagement.lambda.LogMessageTemplates.WRITING_OTP_TO_S_3_BUCKET;
import static uk.gov.di.accountmanagement.lambda.NotificationHandler.EXCEPTION_THROWN_WHEN_WRITING_TO_S_3_BUCKET;
import static uk.gov.di.authentication.entity.Application.ONE_LOGIN_HOME;
import static uk.gov.di.authentication.sharedtest.logging.LogEventMatcher.withMessageContaining;

class NotificationHandlerTest {

    private static final String TEST_EMAIL_ADDRESS = "joe.bloggs@digital.cabinet-office.gov.uk";
    private static final String TEST_PHONE_NUMBER = "01234567890";
    private static final String FRONTEND_BASE_URL = "https://localhost:8080/frontend";
    private static final String CONTACT_US_LINK_ROUTE = "contact-gov-uk-one-login";
    public static final String TEST_NOTIFICATION_CLIENT_EXCEPTION_MESSAGE =
            "test-notification-client-exception";
    public static final String UNEXPECTED_RUNTIME_EXCEPTION_MESSAGE =
            "unexpected-runtime-exception";
    private final Json objectMapper = SerializationService.getInstance();
    private final Context context = mock(Context.class);
    private final NotificationService notificationService = mock(NotificationService.class);
    private final ConfigurationService configService = mock(ConfigurationService.class);
    private final S3Client s3Client = mock(S3Client.class);
    private final CloudwatchMetricsService cloudwatchMetricsService =
            mock(CloudwatchMetricsService.class);
    private final InternationalSmsSendLimitService internationalSmsSendLimitService =
            mock(InternationalSmsSendLimitService.class);
    private NotificationHandler handler;

    @RegisterExtension
    public final CaptureLoggingExtension logging =
            new CaptureLoggingExtension(NotificationHandler.class);

    @BeforeEach
    void setUp() {
        when(configService.getFrontendBaseUrl()).thenReturn(FRONTEND_BASE_URL);
        when(configService.getContactUsLinkRoute()).thenReturn(CONTACT_US_LINK_ROUTE);
        when(configService.getEnvironment()).thenReturn("unit-test");
        when(internationalSmsSendLimitService.canSendSms(anyString())).thenReturn(true);
        handler =
                new NotificationHandler(
                        notificationService,
                        configService,
                        s3Client,
                        cloudwatchMetricsService,
                        internationalSmsSendLimitService);
    }

    @Test
    void shouldSuccessfullyProcessVerifyEmailMessageFromSQSQueue()
            throws Json.JsonException, NotificationClientException {

        NotifyRequest notifyRequest =
                new NotifyRequest(
                        TEST_EMAIL_ADDRESS,
                        VERIFY_EMAIL,
                        "654321",
                        SupportedLanguage.EN,
                        false,
                        null);
        var contactUsLinkUrl = "https://localhost:8080/frontend/" + CONTACT_US_LINK_ROUTE;
        String notifyRequestString = objectMapper.writeValueAsString(notifyRequest);
        SQSEvent sqsEvent = generateSQSEvent(notifyRequestString);

        handler.handleRequest(sqsEvent, context);

        Map<String, Object> personalisation = new HashMap<>();
        personalisation.put("validation-code", "654321");
        personalisation.put("email-address", notifyRequest.getDestination());
        personalisation.put("contact-us-link", contactUsLinkUrl);

        verify(notificationService).sendEmail(TEST_EMAIL_ADDRESS, personalisation, VERIFY_EMAIL);
        assertThat(
                logging.events(),
                hasItem(
                        withMessageContaining(
                                formatMessage(EMAIL_HAS_BEEN_SENT_USING_NOTIFY, VERIFY_EMAIL))));
        verify(cloudwatchMetricsService)
                .emitMetricForNotification(VERIFY_EMAIL, TEST_EMAIL_ADDRESS, false, ONE_LOGIN_HOME);
    }

    @Test
    void shouldHandleEventsWithMissingFieldsInSQSEvent() throws NotificationClientException {
        var event =
                """
                    {
                      "notificationType": "VERIFY_PHONE_NUMBER",
                      "destination": "01234567890",
                      "code": "654321",
                      "language": "EN",
                      "session_id": null,
                      "client_session_id": null
                    }
                """;

        SQSEvent sqsEvent = generateSQSEvent(event);

        handler.handleRequest(sqsEvent, context);

        Map<String, Object> personalisation = new HashMap<>();
        personalisation.put("validation-code", "654321");

        verify(notificationService)
                .sendText(TEST_PHONE_NUMBER, personalisation, VERIFY_PHONE_NUMBER);
        assertThat(
                logging.events(),
                hasItem(
                        withMessageContaining(
                                formatMessage(
                                        TEXT_HAS_BEEN_SENT_USING_NOTIFY, VERIFY_PHONE_NUMBER))));
        verify(cloudwatchMetricsService)
                .emitMetricForNotification(
                        VERIFY_PHONE_NUMBER, TEST_PHONE_NUMBER, false, ONE_LOGIN_HOME);
    }

    @Test
    void shouldHandleEventsWithUnexpectedFieldsInSQSEvent() throws NotificationClientException {
        var event =
                """
                    {
                      "notificationType": "VERIFY_PHONE_NUMBER",
                      "destination": "01234567890",
                      "code": "654321",
                      "language": "EN",
                      "session_id": null,
                      "client_session_id": null,
                      "somethingNew": "and unexpected"
                    }
                """;

        SQSEvent sqsEvent = generateSQSEvent(event);

        handler.handleRequest(sqsEvent, context);

        Map<String, Object> personalisation = new HashMap<>();
        personalisation.put("validation-code", "654321");

        verify(notificationService)
                .sendText(TEST_PHONE_NUMBER, personalisation, VERIFY_PHONE_NUMBER);
        assertThat(
                logging.events(),
                hasItem(
                        withMessageContaining(
                                formatMessage(
                                        TEXT_HAS_BEEN_SENT_USING_NOTIFY, VERIFY_PHONE_NUMBER))));
        verify(cloudwatchMetricsService)
                .emitMetricForNotification(
                        VERIFY_PHONE_NUMBER, TEST_PHONE_NUMBER, false, ONE_LOGIN_HOME);
    }

    @Test
    void shouldSuccessfullyProcessVerifyPhoneMessageFromSQSQueue()
            throws Json.JsonException, NotificationClientException {

        NotifyRequest notifyRequest =
                new NotifyRequest(
                        TEST_PHONE_NUMBER,
                        VERIFY_PHONE_NUMBER,
                        "654321",
                        SupportedLanguage.EN,
                        false,
                        null);
        String notifyRequestString = objectMapper.writeValueAsString(notifyRequest);
        SQSEvent sqsEvent = generateSQSEvent(notifyRequestString);

        handler.handleRequest(sqsEvent, context);

        Map<String, Object> personalisation = new HashMap<>();
        personalisation.put("validation-code", "654321");

        verify(notificationService)
                .sendText(TEST_PHONE_NUMBER, personalisation, VERIFY_PHONE_NUMBER);
        assertThat(
                logging.events(),
                hasItem(
                        withMessageContaining(
                                formatMessage(
                                        TEXT_HAS_BEEN_SENT_USING_NOTIFY, VERIFY_PHONE_NUMBER))));
        verify(cloudwatchMetricsService)
                .emitMetricForNotification(
                        VERIFY_PHONE_NUMBER, TEST_PHONE_NUMBER, false, ONE_LOGIN_HOME);
    }

    @Test
    void shouldSuccessfullyProcessUpdateEmailMessageFromSQSQueue()
            throws Json.JsonException, NotificationClientException {

        NotifyRequest notifyRequest =
                new NotifyRequest(TEST_EMAIL_ADDRESS, EMAIL_UPDATED, SupportedLanguage.EN);
        var contactUsLinkUrl = "https://localhost:8080/frontend/" + CONTACT_US_LINK_ROUTE;
        String notifyRequestString = objectMapper.writeValueAsString(notifyRequest);
        SQSEvent sqsEvent = generateSQSEvent(notifyRequestString);

        handler.handleRequest(sqsEvent, context);

        Map<String, Object> personalisation = new HashMap<>();
        personalisation.put("email-address", notifyRequest.getDestination());
        personalisation.put("contact-us-link", contactUsLinkUrl);

        verify(notificationService).sendEmail(TEST_EMAIL_ADDRESS, personalisation, EMAIL_UPDATED);
        assertThat(
                logging.events(),
                hasItem(
                        withMessageContaining(
                                formatMessage(EMAIL_HAS_BEEN_SENT_USING_NOTIFY, EMAIL_UPDATED))));
        verify(cloudwatchMetricsService)
                .emitMetricForNotification(
                        EMAIL_UPDATED, TEST_EMAIL_ADDRESS, false, ONE_LOGIN_HOME);
    }

    @Test
    void shouldSuccessfullyProcessUpdatePasswordMessageFromSQSQueue()
            throws Json.JsonException, NotificationClientException {

        NotifyRequest notifyRequest =
                new NotifyRequest(TEST_EMAIL_ADDRESS, PASSWORD_UPDATED, SupportedLanguage.EN);
        var contactUsLinkUrl = "https://localhost:8080/frontend/" + CONTACT_US_LINK_ROUTE;
        String notifyRequestString = objectMapper.writeValueAsString(notifyRequest);
        SQSEvent sqsEvent = generateSQSEvent(notifyRequestString);

        handler.handleRequest(sqsEvent, context);

        Map<String, Object> personalisation = new HashMap<>();
        personalisation.put("contact-us-link", contactUsLinkUrl);

        verify(notificationService)
                .sendEmail(TEST_EMAIL_ADDRESS, personalisation, PASSWORD_UPDATED);
        assertThat(
                logging.events(),
                hasItem(
                        withMessageContaining(
                                formatMessage(
                                        EMAIL_HAS_BEEN_SENT_USING_NOTIFY, PASSWORD_UPDATED))));
        verify(cloudwatchMetricsService)
                .emitMetricForNotification(
                        PASSWORD_UPDATED, TEST_EMAIL_ADDRESS, false, ONE_LOGIN_HOME);
    }

    @Test
    void shouldSuccessfullyProcessUpdatePhoneNumberMessageFromSQSQueue()
            throws Json.JsonException, NotificationClientException {

        NotifyRequest notifyRequest =
                new NotifyRequest(TEST_EMAIL_ADDRESS, PHONE_NUMBER_UPDATED, SupportedLanguage.EN);
        var contactUsLinkUrl = "https://localhost:8080/frontend/" + CONTACT_US_LINK_ROUTE;
        String notifyRequestString = objectMapper.writeValueAsString(notifyRequest);
        SQSEvent sqsEvent = generateSQSEvent(notifyRequestString);

        handler.handleRequest(sqsEvent, context);

        Map<String, Object> personalisation = new HashMap<>();
        personalisation.put("contact-us-link", contactUsLinkUrl);

        verify(notificationService)
                .sendEmail(TEST_EMAIL_ADDRESS, personalisation, PHONE_NUMBER_UPDATED);
        assertThat(
                logging.events(),
                hasItem(
                        withMessageContaining(
                                formatMessage(
                                        EMAIL_HAS_BEEN_SENT_USING_NOTIFY, PHONE_NUMBER_UPDATED))));
        verify(cloudwatchMetricsService)
                .emitMetricForNotification(
                        PHONE_NUMBER_UPDATED, TEST_EMAIL_ADDRESS, false, ONE_LOGIN_HOME);
    }

    @Test
    void shouldSuccessfullyProcessDeleteAccountMessageFromSQSQueue()
            throws Json.JsonException, NotificationClientException {

        NotifyRequest notifyRequest =
                new NotifyRequest(TEST_EMAIL_ADDRESS, DELETE_ACCOUNT, SupportedLanguage.EN);
        var contactUsLinkUrl = "https://localhost:8080/frontend/" + CONTACT_US_LINK_ROUTE;
        String notifyRequestString = objectMapper.writeValueAsString(notifyRequest);
        SQSEvent sqsEvent = generateSQSEvent(notifyRequestString);

        handler.handleRequest(sqsEvent, context);

        Map<String, Object> personalisation = new HashMap<>();
        personalisation.put("contact-us-link", contactUsLinkUrl);

        verify(notificationService).sendEmail(TEST_EMAIL_ADDRESS, personalisation, DELETE_ACCOUNT);
        assertThat(
                logging.events(),
                hasItem(
                        withMessageContaining(
                                formatMessage(EMAIL_HAS_BEEN_SENT_USING_NOTIFY, DELETE_ACCOUNT))));
        verify(cloudwatchMetricsService)
                .emitMetricForNotification(
                        DELETE_ACCOUNT, TEST_EMAIL_ADDRESS, false, ONE_LOGIN_HOME);
    }

    @Test
    void shouldSuccessfullyProcessBackupAddedMessageFromSQSQueue()
            throws Json.JsonException, NotificationClientException {

        NotifyRequest notifyRequest =
                new NotifyRequest(TEST_EMAIL_ADDRESS, BACKUP_METHOD_ADDED, SupportedLanguage.EN);

        String notifyRequestString = objectMapper.writeValueAsString(notifyRequest);
        SQSEvent sqsEvent = generateSQSEvent(notifyRequestString);

        handler.handleRequest(sqsEvent, context);

        verify(notificationService)
                .sendEmail(TEST_EMAIL_ADDRESS, Collections.emptyMap(), BACKUP_METHOD_ADDED);
        assertThat(
                logging.events(),
                hasItem(
                        withMessageContaining(
                                formatMessage(
                                        EMAIL_HAS_BEEN_SENT_USING_NOTIFY, BACKUP_METHOD_ADDED))));
        verify(cloudwatchMetricsService)
                .emitMetricForNotification(
                        BACKUP_METHOD_ADDED, TEST_EMAIL_ADDRESS, false, ONE_LOGIN_HOME);
    }

    @Test
    void shouldSuccessfullyProcessBackupRemovedMessageFromSQSQueue()
            throws Json.JsonException, NotificationClientException {

        NotifyRequest notifyRequest =
                new NotifyRequest(TEST_EMAIL_ADDRESS, BACKUP_METHOD_REMOVED, SupportedLanguage.EN);

        String notifyRequestString = objectMapper.writeValueAsString(notifyRequest);
        SQSEvent sqsEvent = generateSQSEvent(notifyRequestString);

        handler.handleRequest(sqsEvent, context);

        verify(notificationService)
                .sendEmail(TEST_EMAIL_ADDRESS, Collections.emptyMap(), BACKUP_METHOD_REMOVED);
        assertThat(
                logging.events(),
                hasItem(
                        withMessageContaining(
                                formatMessage(
                                        EMAIL_HAS_BEEN_SENT_USING_NOTIFY, BACKUP_METHOD_REMOVED))));
        verify(cloudwatchMetricsService)
                .emitMetricForNotification(
                        BACKUP_METHOD_REMOVED, TEST_EMAIL_ADDRESS, false, ONE_LOGIN_HOME);
    }

    @Test
    void shouldSuccessfullyProcessChangedAuthenticatorAppMessageFromSQSQueue()
            throws Json.JsonException, NotificationClientException {

        NotifyRequest notifyRequest =
                new NotifyRequest(
                        TEST_EMAIL_ADDRESS, CHANGED_AUTHENTICATOR_APP, SupportedLanguage.EN);

        String notifyRequestString = objectMapper.writeValueAsString(notifyRequest);
        SQSEvent sqsEvent = generateSQSEvent(notifyRequestString);

        handler.handleRequest(sqsEvent, context);

        verify(notificationService)
                .sendEmail(TEST_EMAIL_ADDRESS, Collections.emptyMap(), CHANGED_AUTHENTICATOR_APP);
        assertThat(
                logging.events(),
                hasItem(
                        withMessageContaining(
                                formatMessage(
                                        EMAIL_HAS_BEEN_SENT_USING_NOTIFY,
                                        CHANGED_AUTHENTICATOR_APP))));
        verify(cloudwatchMetricsService)
                .emitMetricForNotification(
                        CHANGED_AUTHENTICATOR_APP, TEST_EMAIL_ADDRESS, false, ONE_LOGIN_HOME);
    }

    @Test
    void shouldSuccessfullyProcessChangedDefaultMFAMessageFromSQSQueue()
            throws Json.JsonException, NotificationClientException {

        NotifyRequest notifyRequest =
                new NotifyRequest(TEST_EMAIL_ADDRESS, CHANGED_DEFAULT_MFA, SupportedLanguage.EN);

        String notifyRequestString = objectMapper.writeValueAsString(notifyRequest);
        SQSEvent sqsEvent = generateSQSEvent(notifyRequestString);

        handler.handleRequest(sqsEvent, context);

        verify(notificationService)
                .sendEmail(TEST_EMAIL_ADDRESS, Collections.emptyMap(), CHANGED_DEFAULT_MFA);
        assertThat(
                logging.events(),
                hasItem(
                        withMessageContaining(
                                formatMessage(
                                        EMAIL_HAS_BEEN_SENT_USING_NOTIFY, CHANGED_DEFAULT_MFA))));
        verify(cloudwatchMetricsService)
                .emitMetricForNotification(
                        CHANGED_DEFAULT_MFA, TEST_EMAIL_ADDRESS, false, ONE_LOGIN_HOME);
    }

    @Test
    void shouldSuccessfullyProcessSwitchedMFAMethodsMessageFromSQSQueue()
            throws Json.JsonException, NotificationClientException {

        NotifyRequest notifyRequest =
                new NotifyRequest(TEST_EMAIL_ADDRESS, SWITCHED_MFA_METHODS, SupportedLanguage.EN);

        String notifyRequestString = objectMapper.writeValueAsString(notifyRequest);
        SQSEvent sqsEvent = generateSQSEvent(notifyRequestString);

        handler.handleRequest(sqsEvent, context);

        verify(notificationService)
                .sendEmail(TEST_EMAIL_ADDRESS, Collections.emptyMap(), SWITCHED_MFA_METHODS);
        assertThat(
                logging.events(),
                hasItem(
                        withMessageContaining(
                                formatMessage(
                                        EMAIL_HAS_BEEN_SENT_USING_NOTIFY, SWITCHED_MFA_METHODS))));
        verify(cloudwatchMetricsService)
                .emitMetricForNotification(
                        SWITCHED_MFA_METHODS, TEST_EMAIL_ADDRESS, false, ONE_LOGIN_HOME);
    }

    @Test
    void shouldSuccessfullyWriteOTPToS3ForTestClient()
            throws Json.JsonException, NotificationClientException {
        when(configService.getNotifyTestDestinations()).thenReturn(List.of(TEST_PHONE_NUMBER));
        NotifyRequest notifyRequest =
                new NotifyRequest(
                        TEST_PHONE_NUMBER,
                        VERIFY_PHONE_NUMBER,
                        "654321",
                        SupportedLanguage.EN,
                        true,
                        TEST_EMAIL_ADDRESS);
        String notifyRequestString = objectMapper.writeValueAsString(notifyRequest);
        SQSEvent sqsEvent = generateSQSEvent(notifyRequestString);

        handler.handleRequest(sqsEvent, context);

        verify(s3Client).putObject((PutObjectRequest) any(), (RequestBody) any());
        verify(notificationService, never()).sendText(any(), any(), any());
        assertThat(
                logging.events(),
                hasItem(
                        withMessageContaining(
                                formatMessage(
                                        NOTIFY_TEST_DESTINATION_USED_WRITING_TO_S3_BUCKET,
                                        VERIFY_PHONE_NUMBER))));
        verifyNoInteractions(cloudwatchMetricsService);
    }

    @Test
    void shouldDoNothingForTestUserOnTheListSendingNonOTPNotification()
            throws Json.JsonException, NotificationClientException {
        when(configService.getNotifyTestDestinations()).thenReturn(List.of(TEST_PHONE_NUMBER));
        NotifyRequest notifyRequest =
                new NotifyRequest(
                        TEST_PHONE_NUMBER,
                        EMAIL_UPDATED,
                        "654321",
                        SupportedLanguage.EN,
                        true,
                        TEST_EMAIL_ADDRESS);
        String notifyRequestString = objectMapper.writeValueAsString(notifyRequest);
        SQSEvent sqsEvent = generateSQSEvent(notifyRequestString);

        handler.handleRequest(sqsEvent, context);

        verify(s3Client, never()).putObject((PutObjectRequest) any(), (RequestBody) any());
        verify(notificationService, never()).sendText(any(), any(), any());
        assertThat(
                logging.events(),
                hasItem(
                        withMessageContaining(
                                formatMessage(
                                        NOT_WRITING_TO_BUCKET_AS_NOT_OTP_NOTIFICATION,
                                        EMAIL_UPDATED))));
        verifyNoInteractions(cloudwatchMetricsService);
    }

    @Test
    void shouldSuccessfullyLogWritingToS3InIntegration()
            throws Json.JsonException, NotificationClientException {
        when(configService.getNotifyTestDestinations()).thenReturn(List.of(TEST_PHONE_NUMBER));
        when(configService.getEnvironment()).thenReturn("integration");
        NotifyRequest notifyRequest =
                new NotifyRequest(
                        TEST_PHONE_NUMBER,
                        VERIFY_PHONE_NUMBER,
                        "654321",
                        SupportedLanguage.EN,
                        true,
                        TEST_EMAIL_ADDRESS);
        String notifyRequestString = objectMapper.writeValueAsString(notifyRequest);
        SQSEvent sqsEvent = generateSQSEvent(notifyRequestString);

        handler.handleRequest(sqsEvent, context);

        verify(s3Client).putObject((PutObjectRequest) any(), (RequestBody) any());
        verify(notificationService, never()).sendText(any(), any(), any());
        assertThat(
                logging.events(),
                hasItem(
                        withMessageContaining(
                                formatMessage(
                                        NOTIFY_TEST_DESTINATION_USED_WRITING_TO_S3_BUCKET,
                                        VERIFY_PHONE_NUMBER))));
        assertThat(
                logging.events(),
                hasItem(withMessageContaining(formatMessage(WRITING_OTP_TO_S_3_BUCKET, "654321"))));
        verifyNoInteractions(cloudwatchMetricsService);
    }

    @Test
    void shouldReportErrorWritingToS3() throws Json.JsonException, NotificationClientException {
        when(configService.getNotifyTestDestinations()).thenReturn(List.of(TEST_PHONE_NUMBER));
        when(configService.getEnvironment()).thenReturn("integration");
        var s3failException = new RuntimeException("s3 failed");
        when(s3Client.putObject((PutObjectRequest) any(), (RequestBody) any()))
                .thenThrow(s3failException);
        NotifyRequest notifyRequest =
                new NotifyRequest(
                        TEST_PHONE_NUMBER,
                        VERIFY_PHONE_NUMBER,
                        "654321",
                        SupportedLanguage.EN,
                        true,
                        TEST_EMAIL_ADDRESS);
        String notifyRequestString = objectMapper.writeValueAsString(notifyRequest);
        SQSEvent sqsEvent = generateSQSEvent(notifyRequestString);

        handler.handleRequest(sqsEvent, context);

        verify(s3Client).putObject((PutObjectRequest) any(), (RequestBody) any());
        verify(notificationService, never()).sendText(any(), any(), any());
        assertThat(
                logging.events(),
                hasItem(
                        withMessageContaining(
                                formatMessage(
                                        NOTIFY_TEST_DESTINATION_USED_WRITING_TO_S3_BUCKET,
                                        VERIFY_PHONE_NUMBER))));
        assertThat(
                logging.events(),
                hasItem(
                        withMessageContaining(
                                formatMessage(
                                        EXCEPTION_THROWN_WHEN_WRITING_TO_S_3_BUCKET,
                                        "s3 failed",
                                        s3failException))));
        verifyNoInteractions(cloudwatchMetricsService);
    }

    @Test
    void checkHandlesInvalidMessageWithoutEscapedException() {
        String invalidMessage =
                """
                {
                    "type": "invalid"
                    "destination": "test@example.com"
                }
                """;
        var sqsEvent = generateSQSEvent(invalidMessage);

        handler.handleRequest(sqsEvent, context);

        assertThat(
                logging.events(),
                hasItem(
                        withMessageContaining(
                                "Error when mapping message from queue to a NotifyRequest")));
    }

    private static String formatMessage(String template, Object... args) {
        String result = template;
        for (Object arg : args) {
            result = result.replaceFirst("\\{}", arg.toString());
        }
        return result;
    }

    private static Stream<Arguments> notificationServiceExceptionProvider() {
        String messageWhenNotifyClientException =
                formatMessage(
                        ERROR_SENDING_WITH_NOTIFY, TEST_NOTIFICATION_CLIENT_EXCEPTION_MESSAGE);
        return Stream.of(
                Arguments.of(
                        new NotificationClientException(TEST_NOTIFICATION_CLIENT_EXCEPTION_MESSAGE),
                        messageWhenNotifyClientException,
                        VERIFY_EMAIL),
                Arguments.of(
                        new RuntimeException(UNEXPECTED_RUNTIME_EXCEPTION_MESSAGE),
                        formatMessage(
                                UNEXPECTED_ERROR_SENDING_NOTIFICATION,
                                VERIFY_EMAIL,
                                UNEXPECTED_RUNTIME_EXCEPTION_MESSAGE),
                        VERIFY_EMAIL),
                Arguments.of(
                        new NotificationClientException(TEST_NOTIFICATION_CLIENT_EXCEPTION_MESSAGE),
                        messageWhenNotifyClientException,
                        VERIFY_PHONE_NUMBER),
                Arguments.of(
                        new RuntimeException(UNEXPECTED_RUNTIME_EXCEPTION_MESSAGE),
                        formatMessage(
                                UNEXPECTED_ERROR_SENDING_NOTIFICATION,
                                VERIFY_PHONE_NUMBER,
                                UNEXPECTED_RUNTIME_EXCEPTION_MESSAGE),
                        VERIFY_PHONE_NUMBER));
    }

    @ParameterizedTest
    @MethodSource("notificationServiceExceptionProvider")
    void shouldLogWithoutThrowingAnExceptionWhenClientErrorSendingToNotify(
            Exception exception, String expectedMessage, NotificationType type)
            throws Json.JsonException, NotificationClientException {
        NotifyRequest notifyRequest =
                new NotifyRequest(
                        TEST_PHONE_NUMBER, type, "654321", SupportedLanguage.EN, false, null);
        String notifyRequestString = objectMapper.writeValueAsString(notifyRequest);
        SQSEvent sqsEvent = generateSQSEvent(notifyRequestString);

        doThrow(exception).when(notificationService).sendEmail(any(), any(), any());
        doThrow(exception).when(notificationService).sendText(any(), any(), any());

        handler.handleRequest(sqsEvent, context);

        assertThat(logging.events(), hasItem(withMessageContaining(expectedMessage)));

        if (exception instanceof NotificationClientException) {
            verify(cloudwatchMetricsService)
                    .emitMetricForNotificationError(
                            type,
                            TEST_PHONE_NUMBER,
                            false,
                            ONE_LOGIN_HOME,
                            (NotificationClientException) exception);
        }
    }

    @Test
    void shouldRecordSmsSentAfterSuccessfulSmsSend()
            throws Json.JsonException, NotificationClientException {
        when(internationalSmsSendLimitService.canSendSms(anyString())).thenReturn(true);

        NotifyRequest notifyRequest =
                new NotifyRequest(
                        CommonTestVariables.INTERNATIONAL_MOBILE_NUMBER,
                        VERIFY_PHONE_NUMBER,
                        "123456",
                        SupportedLanguage.EN,
                        "session-id",
                        "client-session-id");
        String notifyRequestString = objectMapper.writeValueAsString(notifyRequest);
        SQSEvent sqsEvent = generateSQSEvent(notifyRequestString);

        handler.handleRequest(sqsEvent, context);

        verify(internationalSmsSendLimitService)
                .canSendSms(CommonTestVariables.INTERNATIONAL_MOBILE_NUMBER);
        verify(notificationService)
                .sendText(
                        eq(CommonTestVariables.INTERNATIONAL_MOBILE_NUMBER), any(Map.class), any());
        verify(internationalSmsSendLimitService)
                .recordSmsSent(
                        eq(CommonTestVariables.INTERNATIONAL_MOBILE_NUMBER),
                        eq("client-session-id"));
    }

    @Test
    void shouldNotSendSmsWhenInternationalLimitReached() throws Json.JsonException {
        when(internationalSmsSendLimitService.canSendSms(anyString())).thenReturn(false);

        NotifyRequest notifyRequest =
                new NotifyRequest(
                        CommonTestVariables.INTERNATIONAL_MOBILE_NUMBER,
                        VERIFY_PHONE_NUMBER,
                        "123456",
                        SupportedLanguage.EN,
                        "session-id",
                        "client-session-id");
        String notifyRequestString = objectMapper.writeValueAsString(notifyRequest);
        SQSEvent sqsEvent = generateSQSEvent(notifyRequestString);

        handler.handleRequest(sqsEvent, context);

        verify(internationalSmsSendLimitService)
                .canSendSms(CommonTestVariables.INTERNATIONAL_MOBILE_NUMBER);
        verifyNoInteractions(notificationService);
        verify(internationalSmsSendLimitService, never()).recordSmsSent(anyString(), anyString());
        assertThat(
                logging.events(),
                hasItem(
                        withMessageContaining(
                                "International SMS send limit reached. NotificationType: VERIFY_PHONE_NUMBER")));
    }

    private SQSEvent generateSQSEvent(String messageBody) {
        SQSMessage sqsMessage = new SQSMessage();
        sqsMessage.setBody(messageBody);
        SQSEvent sqsEvent = new SQSEvent();
        sqsEvent.setRecords(singletonList(sqsMessage));
        return sqsEvent;
    }
}
