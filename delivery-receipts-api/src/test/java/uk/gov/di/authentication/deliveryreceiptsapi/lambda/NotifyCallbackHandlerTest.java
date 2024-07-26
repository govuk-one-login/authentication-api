package uk.gov.di.authentication.deliveryreceiptsapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.authentication.deliveryreceiptsapi.entity.NotifyDeliveryReceipt;
import uk.gov.di.authentication.shared.entity.DeliveryReceiptsNotificationType;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.helpers.IdGenerator;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.BulkEmailUsersService;
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.SerializationService;
import uk.gov.di.authentication.sharedtest.logging.CaptureLoggingExtension;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Date;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyDouble;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.shared.entity.DeliveryReceiptsNotificationType.EMAIL_UPDATED;
import static uk.gov.di.authentication.shared.entity.DeliveryReceiptsNotificationType.TERMS_AND_CONDITIONS_BULK_EMAIL;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class NotifyCallbackHandlerTest {

    private static final String BEARER_TOKEN = "1244656456457657566345";
    private static final String ENVIRONMENT = "test";
    private NotifyCallbackHandler handler;

    private final Context context = mock(Context.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final DynamoService dynamoService = mock(DynamoService.class);

    private final BulkEmailUsersService bulkEmailUsersService = mock(BulkEmailUsersService.class);
    private final CloudwatchMetricsService cloudwatchMetricsService =
            mock(CloudwatchMetricsService.class);
    private final Json objectMapper = SerializationService.getInstance();
    private static final String TEMPLATE_ID = IdGenerator.generate();

    @RegisterExtension
    public final CaptureLoggingExtension logging =
            new CaptureLoggingExtension(NotifyCallbackHandler.class);

    @BeforeEach
    void setup() {
        when(configurationService.getNotifyCallbackBearerToken()).thenReturn(BEARER_TOKEN);
        when(configurationService.getEnvironment()).thenReturn(ENVIRONMENT);
        handler =
                new NotifyCallbackHandler(
                        cloudwatchMetricsService,
                        configurationService,
                        dynamoService,
                        bulkEmailUsersService);
    }

    private static Stream<Arguments> phoneNumbers() {
        return Stream.of(
                Arguments.of("+447316763843", "44", "delivered"),
                Arguments.of("+4407316763843", "44", "delivered"),
                Arguments.of("+33645453322", "33", "delivered"),
                Arguments.of("+330645453322", "33", "delivered"),
                Arguments.of("+447316763843", "44", "delivered"),
                Arguments.of("+447316763843", "44", "delivered"),
                Arguments.of("+33645453322", "33", "delivered"),
                Arguments.of("+33645453322", "33", "delivered"),
                Arguments.of("07911123456", "44", "delivered"),
                Arguments.of("+447316763843", "44", "permanent-failure"),
                Arguments.of("+4407316763843", "44", "permanent-failure"),
                Arguments.of("+330645453322", "33", "technical-failure"),
                Arguments.of("+33645453322", "33", "technical-failure"),
                Arguments.of("07911123456", "44", "temporary-failure"),
                Arguments.of("+447316763843", "44", "temporary-failure"));
    }

    @ParameterizedTest
    @MethodSource("phoneNumbers")
    void shouldCallCloudwatchMetricServiceWhenSmsReceiptIsReceived(
            String number, String expectedCountryCode, String status) throws Json.JsonException {
        var templateID = IdGenerator.generate();
        when(configurationService.getNotificationTypeFromTemplateId(templateID))
                .thenReturn(Optional.of(DeliveryReceiptsNotificationType.VERIFY_PHONE_NUMBER));
        var deliveryReceipt = createDeliveryReceipt(number, status, "sms", templateID);
        var response = handler.handleRequest(eventWithBody(deliveryReceipt), context);

        verify(cloudwatchMetricsService)
                .incrementCounter(
                        "SmsSent",
                        Map.of(
                                "SmsType",
                                DeliveryReceiptsNotificationType.VERIFY_PHONE_NUMBER
                                        .getTemplateAlias(),
                                "CountryCode",
                                expectedCountryCode,
                                "Environment",
                                ENVIRONMENT,
                                "NotifyStatus",
                                status));

        assertThat(response, hasStatus(204));
    }

    @Test
    void
            shouldSendCloudwatchDurationInMillisecondsBetweenCreatedAndAndUpdatedAtForDeliveredRequest()
                    throws Json.JsonException {
        when(configurationService.getNotificationTypeFromTemplateId(TEMPLATE_ID))
                .thenReturn(Optional.of(DeliveryReceiptsNotificationType.VERIFY_PHONE_NUMBER));
        var createdAtDate = Instant.now();
        var completedAt = createdAtDate.plusMillis(1000);
        var deliveryReceipt =
                deliveryReceiptWithCreatedAtAndCompletedAt(
                        "sms", "delivered", createdAtDate, completedAt);
        var response = handler.handleRequest(eventWithBody(deliveryReceipt), context);

        verify(cloudwatchMetricsService)
                .putEmbeddedValue(
                        "NotifyDeliveryDuration",
                        1000,
                        Map.of("Environment", ENVIRONMENT, "NotificationType", "sms"));

        assertThat(response, hasStatus(204));
    }

    @Test
    void
            shouldNotSendCloudwatchDurationInMillisecondsBetweenCreatedAndAndUpdatedAtForAnUnsuccessfulReceipt()
                    throws Json.JsonException {
        when(configurationService.getNotificationTypeFromTemplateId(TEMPLATE_ID))
                .thenReturn(Optional.of(DeliveryReceiptsNotificationType.VERIFY_PHONE_NUMBER));
        var deliveryStatus = "permanentFailure";
        var deliveryReceipt =
                deliveryReceiptWithCreatedAtAndCompletedAt(
                        "sms", deliveryStatus, Instant.now(), Instant.now().plusMillis(1));
        var response = handler.handleRequest(eventWithBody(deliveryReceipt), context);

        verify(cloudwatchMetricsService, never()).putEmbeddedValue(any(), anyDouble(), any());

        assertThat(response, hasStatus(204));
    }

    @Test
    void shouldNotThrowAnErrorWhenMetricsParsingFails() throws Json.JsonException {
        when(configurationService.getNotificationTypeFromTemplateId(TEMPLATE_ID))
                .thenReturn(Optional.of(DeliveryReceiptsNotificationType.VERIFY_PHONE_NUMBER));
        var invalidCreatedAtDate = "not-a-date";
        var deliveryReceipt =
                createDeliveryReceipt(
                        "some-reference",
                        "+447316763843",
                        "delivered",
                        "sms",
                        TEMPLATE_ID,
                        invalidCreatedAtDate,
                        formattedDate(Instant.now()),
                        formattedDate(Instant.now()));
        var response = handler.handleRequest(eventWithBody(deliveryReceipt), context);

        verify(cloudwatchMetricsService, never()).putEmbeddedValue(any(), anyDouble(), any());

        assertThat(response, hasStatus(204));
    }

    private static Stream<DeliveryReceiptsNotificationType> emailTemplates() {
        return Stream.of(
                DeliveryReceiptsNotificationType.TERMS_AND_CONDITIONS_BULK_EMAIL,
                DeliveryReceiptsNotificationType.VERIFY_EMAIL);
    }

    @ParameterizedTest
    @MethodSource("emailTemplates")
    void shouldCallCloudwatchMetricWithEmailNotificationType(DeliveryReceiptsNotificationType type)
            throws Json.JsonException {
        var templateID = IdGenerator.generate();
        when(configurationService.getNotificationTypeFromTemplateId(templateID))
                .thenReturn(Optional.of(type));
        var deliveryReceipt =
                createDeliveryReceipt("jim@test.com", "delivered", "email", templateID);
        handler.handleRequest(eventWithBody(deliveryReceipt), context);

        verify(cloudwatchMetricsService)
                .incrementCounter(
                        "EmailSent",
                        Map.of(
                                "EmailName",
                                type.getTemplateAlias(),
                                "Environment",
                                ENVIRONMENT,
                                "NotifyStatus",
                                "delivered"));
    }

    @Test
    void shouldUpdateBulkEmailDeliveryReceiptsStatusForTermsAndConditionsEmailType()
            throws Json.JsonException {
        String email = "jim@test.com";
        var templateID = IdGenerator.generate();
        when(configurationService.getNotificationTypeFromTemplateId(templateID))
                .thenReturn(Optional.of(TERMS_AND_CONDITIONS_BULK_EMAIL));
        when(configurationService.isBulkUserEmailEnabled()).thenReturn(true);
        NotifyCallbackHandler handlerBulkEmailOn =
                new NotifyCallbackHandler(
                        cloudwatchMetricsService,
                        configurationService,
                        dynamoService,
                        bulkEmailUsersService);
        var deliveryReceipt = createDeliveryReceipt(email, "delivered", "email", templateID);
        String subjectId = "subject-id-1";
        UserProfile userProfile = new UserProfile().withEmail(email).withSubjectID(subjectId);
        when(dynamoService.getUserProfileByEmailMaybe(email)).thenReturn(Optional.of(userProfile));
        handlerBulkEmailOn.handleRequest(eventWithBody(deliveryReceipt), context);

        verify(dynamoService).getUserProfileByEmailMaybe(email);

        verify(bulkEmailUsersService).updateDeliveryReceiptStatus(subjectId, "delivered");
    }

    @Test
    void
            shouldNotUpdateBulkEmailDeliveryReceiptsStatusForTermsAndConditionsEmailTypeWhenBulkEmailSwitchedOn()
                    throws Json.JsonException {
        String email = "jim@test.com";
        var templateID = IdGenerator.generate();
        when(configurationService.getNotificationTypeFromTemplateId(templateID))
                .thenReturn(Optional.of(EMAIL_UPDATED));
        NotifyCallbackHandler handlerBulkEmailOn =
                new NotifyCallbackHandler(
                        cloudwatchMetricsService,
                        configurationService,
                        dynamoService,
                        bulkEmailUsersService);
        var deliveryReceipt = createDeliveryReceipt(email, "delivered", "email", templateID);
        handlerBulkEmailOn.handleRequest(eventWithBody(deliveryReceipt), context);

        verify(dynamoService, never()).getUserProfileByEmailMaybe(anyString());
        verify(bulkEmailUsersService, never())
                .updateDeliveryReceiptStatus(anyString(), anyString());
    }

    @Test
    void shouldNotUpdateBulkEmailDeliveryReceiptsStatusWhenBulkEmailSwitchedOff()
            throws Json.JsonException {
        String email = "jim@test.com";
        var templateID = IdGenerator.generate();
        when(configurationService.getNotificationTypeFromTemplateId(templateID))
                .thenReturn(Optional.of(TERMS_AND_CONDITIONS_BULK_EMAIL));
        var deliveryReceipt = createDeliveryReceipt(email, "delivered", "email", templateID);
        handler.handleRequest(eventWithBody(deliveryReceipt), context);

        verify(dynamoService, never()).getUserProfileByEmailMaybe(anyString());
        verify(bulkEmailUsersService, never())
                .updateDeliveryReceiptStatus(anyString(), anyString());
    }

    @Test
    void shouldNotUpdateBulkEmailDeliveryReceiptsStatusForEmailUpdatedEmailType()
            throws Json.JsonException {
        String email = "jim@test.com";
        var templateID = IdGenerator.generate();
        when(configurationService.getNotificationTypeFromTemplateId(templateID))
                .thenReturn(Optional.of(EMAIL_UPDATED));
        when(configurationService.isBulkUserEmailEnabled()).thenReturn(true);
        NotifyCallbackHandler handlerBulkEmailOn =
                new NotifyCallbackHandler(
                        cloudwatchMetricsService,
                        configurationService,
                        dynamoService,
                        bulkEmailUsersService);
        var deliveryReceipt = createDeliveryReceipt(email, "delivered", "email", templateID);
        handlerBulkEmailOn.handleRequest(eventWithBody(deliveryReceipt), context);

        verify(dynamoService, never()).getUserProfileByEmailMaybe(anyString());
        verify(bulkEmailUsersService, never())
                .updateDeliveryReceiptStatus(anyString(), anyString());
    }

    @Test
    void shouldThrowIfInvalidTemplateId() throws Json.JsonException {
        var templateID = IdGenerator.generate();
        when(configurationService.getNotificationTypeFromTemplateId(templateID))
                .thenReturn(Optional.empty());
        var deliveryReceipt =
                createDeliveryReceipt("jim@test.com", "delivered", "email", templateID);

        var event = eventWithBody(deliveryReceipt);

        assertThrows(
                RuntimeException.class,
                () -> handler.handleRequest(event, context),
                "Expected to throw exception");

        verifyNoInteractions(cloudwatchMetricsService);
    }

    @Test
    void shouldThrowIfBearerTokenIsMissing() {
        var event = new APIGatewayProxyRequestEvent().withHeaders(Map.of());

        var exception =
                assertThrows(
                        RuntimeException.class,
                        () -> handler.handleRequest(event, context),
                        "Expected to throw exception");

        verifyNoInteractions(cloudwatchMetricsService);
        assertThat(exception.getMessage(), equalTo("No bearer token in request"));
    }

    @Test
    void shouldThrowIfBearerTokenIsInvalid() {
        var event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("Authorization", "Bearer gfdgfdgfdgdsfgdsf"));

        var exception =
                assertThrows(
                        RuntimeException.class,
                        () -> handler.handleRequest(event, context),
                        "Expected to throw exception");

        verifyNoInteractions(cloudwatchMetricsService);
        assertThat(exception.getMessage(), equalTo("Invalid bearer token in request"));
    }

    @Test
    void shouldThrowIfBearerTokenIsNotPrefixedWithBearer() {
        var event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("Authorization", BEARER_TOKEN));

        var exception =
                assertThrows(
                        RuntimeException.class,
                        () -> handler.handleRequest(event, context),
                        "Expected to throw exception");

        verifyNoInteractions(cloudwatchMetricsService);
        assertThat(exception.getMessage(), equalTo("No bearer token in request"));
    }

    @Test
    void shouldParsePayloadWithExpectedNullValues() {
        assertDoesNotThrow(
                () -> {
                    var templateID = IdGenerator.generate();
                    when(configurationService.getNotificationTypeFromTemplateId(templateID))
                            .thenReturn(
                                    Optional.of(
                                            DeliveryReceiptsNotificationType.VERIFY_PHONE_NUMBER));
                    var deliveryReceipt =
                            createDeliveryReceipt(
                                    null,
                                    "+447316763843",
                                    "delivered",
                                    "sms",
                                    templateID,
                                    new Date().toString(),
                                    null,
                                    null);
                    handler.handleRequest(eventWithBody(deliveryReceipt), context);
                });
    }

    private NotifyDeliveryReceipt createDeliveryReceipt(
            String reference,
            String destination,
            String status,
            String notificationType,
            String templateID,
            String createdAt,
            String completedAt,
            String sentAt) {
        return new NotifyDeliveryReceipt(
                IdGenerator.generate(),
                reference,
                destination,
                status,
                createdAt,
                completedAt,
                sentAt,
                notificationType,
                templateID,
                1);
    }

    private NotifyDeliveryReceipt createDeliveryReceipt(
            String destination, String status, String notificationType, String templateID) {
        return createDeliveryReceipt(
                null,
                destination,
                status,
                notificationType,
                templateID,
                formattedDate(Instant.now()),
                formattedDate(Instant.now()),
                formattedDate(Instant.now()));
    }

    String formattedDate(Instant date) {
        var zonedDateTime = ZonedDateTime.ofInstant(date, ZoneOffset.UTC);
        return DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSSSSS'Z'").format(zonedDateTime);
    }

    private NotifyDeliveryReceipt deliveryReceiptWithCreatedAtAndCompletedAt(
            String notificationType, String status, Instant createdAt, Instant completedAt) {
        return createDeliveryReceipt(
                "some-reference",
                "+447316763843",
                status,
                notificationType,
                TEMPLATE_ID,
                formattedDate(createdAt),
                formattedDate(completedAt),
                formattedDate(Instant.now()));
    }

    private APIGatewayProxyRequestEvent eventWithBody(NotifyDeliveryReceipt body)
            throws Json.JsonException {
        return new APIGatewayProxyRequestEvent()
                .withHeaders(Map.of("Authorization", "Bearer " + BEARER_TOKEN))
                .withBody(objectMapper.writeValueAsString(body));
    }
}
