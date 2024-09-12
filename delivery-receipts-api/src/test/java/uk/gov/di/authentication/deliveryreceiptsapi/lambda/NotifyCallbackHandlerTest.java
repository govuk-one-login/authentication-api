package uk.gov.di.authentication.deliveryreceiptsapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import org.apache.logging.log4j.core.LogEvent;
import org.hamcrest.Description;
import org.hamcrest.Matcher;
import org.hamcrest.TypeSafeMatcher;
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
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
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
import static uk.gov.di.authentication.shared.entity.DeliveryReceiptsNotificationType.VERIFY_PHONE_NUMBER;
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
    private static final String EMAIL = "jim@test.com";
    private static final String UK_PHONE_NUMBER = "+44123456788";

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
        setupNotifyTemplate(Optional.of(VERIFY_PHONE_NUMBER));
        var reference = UUID.randomUUID().toString();
        var deliveryReceipt = createDeliveryReceipt(number, status, "sms", TEMPLATE_ID, reference);
        var response = handler.handleRequest(eventWithBody(deliveryReceipt), context);

        var expectedContext =
                Map.ofEntries(
                        Map.entry("SmsType", VERIFY_PHONE_NUMBER.getTemplateAlias()),
                        Map.entry("CountryCode", expectedCountryCode),
                        Map.entry("Environment", ENVIRONMENT),
                        Map.entry("NotifyStatus", status));

        verify(cloudwatchMetricsService).incrementCounter("SmsSent", expectedContext);

        assertThat(response, hasStatus(204));
        assertThat(logging.events(), haveJourneyId(reference));
    }

    @Test
    void
            shouldSendCloudwatchDurationInMillisecondsBetweenCreatedAndAndUpdatedAtForDeliveredRequest()
                    throws Json.JsonException {
        setupNotifyTemplate(Optional.of(VERIFY_PHONE_NUMBER));
        var createdAtDate = Instant.now();
        var completedAt = createdAtDate.plusMillis(1000);
        var reference = UUID.randomUUID().toString();
        var deliveryReceipt =
                deliveryReceiptWithCreatedAtAndCompletedAt(
                        "sms", "delivered", createdAtDate, completedAt, reference);
        var response = handler.handleRequest(eventWithBody(deliveryReceipt), context);

        var expectedContext = Map.of("Environment", ENVIRONMENT, "NotificationType", "sms");

        verify(cloudwatchMetricsService)
                .putEmbeddedValue("NotifyDeliveryDuration", 1000, expectedContext);

        assertThat(response, hasStatus(204));
        assertThat(logging.events(), haveJourneyId(reference));
    }

    @Test
    void
            shouldNotSendCloudwatchDurationInMillisecondsBetweenCreatedAndAndUpdatedAtForAnUnsuccessfulReceipt()
                    throws Json.JsonException {
        setupNotifyTemplate(Optional.of(VERIFY_PHONE_NUMBER));
        var deliveryStatus = "permanentFailure";
        var reference = UUID.randomUUID().toString();
        var deliveryReceipt =
                deliveryReceiptWithCreatedAtAndCompletedAt(
                        "sms",
                        deliveryStatus,
                        Instant.now(),
                        Instant.now().plusMillis(1),
                        reference);
        var response = handler.handleRequest(eventWithBody(deliveryReceipt), context);

        verify(cloudwatchMetricsService, never()).putEmbeddedValue(any(), anyDouble(), any());

        assertThat(response, hasStatus(204));
        assertThat(logging.events(), haveJourneyId(reference));
    }

    @Test
    void shouldNotThrowAnErrorWhenMetricsParsingFails() throws Json.JsonException {
        setupNotifyTemplate(Optional.of(VERIFY_PHONE_NUMBER));
        var invalidCreatedAtDate = "not-a-date";
        var reference = UUID.randomUUID().toString();
        var deliveryReceipt =
                createDeliveryReceipt(
                        reference,
                        UK_PHONE_NUMBER,
                        "delivered",
                        "sms",
                        TEMPLATE_ID,
                        invalidCreatedAtDate,
                        formattedDate(Instant.now()),
                        formattedDate(Instant.now()));
        var response = handler.handleRequest(eventWithBody(deliveryReceipt), context);

        verify(cloudwatchMetricsService, never()).putEmbeddedValue(any(), anyDouble(), any());

        assertThat(response, hasStatus(204));
        assertThat(logging.events(), haveJourneyId(reference));
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
        setupNotifyTemplate(Optional.of(type));
        var reference = UUID.randomUUID().toString();
        var deliveryReceipt =
                createDeliveryReceipt(EMAIL, "delivered", "email", TEMPLATE_ID, reference);
        handler.handleRequest(eventWithBody(deliveryReceipt), context);

        var expectedMetricsContext =
                Map.ofEntries(
                        Map.entry("EmailName", type.getTemplateAlias()),
                        Map.entry("Environment", ENVIRONMENT),
                        Map.entry("NotifyStatus", "delivered"));

        verify(cloudwatchMetricsService).incrementCounter("EmailSent", expectedMetricsContext);
        assertThat(logging.events(), haveJourneyId(reference));
    }

    @Test
    void shouldUpdateBulkEmailDeliveryReceiptsStatusForTermsAndConditionsEmailType()
            throws Json.JsonException {
        setupNotifyTemplate(Optional.of(TERMS_AND_CONDITIONS_BULK_EMAIL));
        when(configurationService.isBulkUserEmailEnabled()).thenReturn(true);
        NotifyCallbackHandler handlerBulkEmailOn =
                new NotifyCallbackHandler(
                        cloudwatchMetricsService,
                        configurationService,
                        dynamoService,
                        bulkEmailUsersService);
        var reference = UUID.randomUUID().toString();
        var deliveryReceipt =
                createDeliveryReceipt(EMAIL, "delivered", "email", TEMPLATE_ID, reference);
        String subjectId = "subject-id-1";
        UserProfile userProfile = new UserProfile().withEmail(EMAIL).withSubjectID(subjectId);
        when(dynamoService.getUserProfileByEmailMaybe(EMAIL)).thenReturn(Optional.of(userProfile));
        handlerBulkEmailOn.handleRequest(eventWithBody(deliveryReceipt), context);

        verify(dynamoService).getUserProfileByEmailMaybe(EMAIL);

        verify(bulkEmailUsersService).updateDeliveryReceiptStatus(subjectId, "delivered");
        assertThat(logging.events(), haveJourneyId(reference));
    }

    @Test
    void
            shouldNotUpdateBulkEmailDeliveryReceiptsStatusForTermsAndConditionsEmailTypeWhenBulkEmailSwitchedOn()
                    throws Json.JsonException {
        setupNotifyTemplate(Optional.of(EMAIL_UPDATED));
        NotifyCallbackHandler handlerBulkEmailOn =
                new NotifyCallbackHandler(
                        cloudwatchMetricsService,
                        configurationService,
                        dynamoService,
                        bulkEmailUsersService);
        var reference = UUID.randomUUID().toString();
        var deliveryReceipt =
                createDeliveryReceipt(EMAIL, "delivered", "email", TEMPLATE_ID, reference);
        handlerBulkEmailOn.handleRequest(eventWithBody(deliveryReceipt), context);

        verify(dynamoService, never()).getUserProfileByEmailMaybe(anyString());
        verify(bulkEmailUsersService, never())
                .updateDeliveryReceiptStatus(anyString(), anyString());
        assertThat(logging.events(), haveJourneyId(reference));
    }

    @Test
    void shouldNotUpdateBulkEmailDeliveryReceiptsStatusWhenBulkEmailSwitchedOff()
            throws Json.JsonException {
        setupNotifyTemplate(Optional.of(TERMS_AND_CONDITIONS_BULK_EMAIL));
        var reference = UUID.randomUUID().toString();
        var deliveryReceipt =
                createDeliveryReceipt(EMAIL, "delivered", "email", TEMPLATE_ID, reference);
        handler.handleRequest(eventWithBody(deliveryReceipt), context);

        verify(dynamoService, never()).getUserProfileByEmailMaybe(anyString());
        verify(bulkEmailUsersService, never())
                .updateDeliveryReceiptStatus(anyString(), anyString());
        assertThat(logging.events(), haveJourneyId(reference));
    }

    @Test
    void shouldNotUpdateBulkEmailDeliveryReceiptsStatusForEmailUpdatedEmailType()
            throws Json.JsonException {
        setupNotifyTemplate(Optional.of(EMAIL_UPDATED));
        when(configurationService.isBulkUserEmailEnabled()).thenReturn(true);
        NotifyCallbackHandler handlerBulkEmailOn =
                new NotifyCallbackHandler(
                        cloudwatchMetricsService,
                        configurationService,
                        dynamoService,
                        bulkEmailUsersService);
        var reference = UUID.randomUUID().toString();
        var deliveryReceipt =
                createDeliveryReceipt(EMAIL, "delivered", "email", TEMPLATE_ID, reference);
        handlerBulkEmailOn.handleRequest(eventWithBody(deliveryReceipt), context);

        verify(dynamoService, never()).getUserProfileByEmailMaybe(anyString());
        verify(bulkEmailUsersService, never())
                .updateDeliveryReceiptStatus(anyString(), anyString());
        assertThat(logging.events(), haveJourneyId(reference));
    }

    @Test
    void shouldThrowIfInvalidTemplateId() throws Json.JsonException {
        setupNotifyTemplate(Optional.empty());
        var reference = UUID.randomUUID().toString();
        var deliveryReceipt =
                createDeliveryReceipt(EMAIL, "delivered", "email", TEMPLATE_ID, reference);

        var event = eventWithBody(deliveryReceipt);

        assertThrows(
                RuntimeException.class,
                () -> handler.handleRequest(event, context),
                "Expected to throw exception");

        verifyNoInteractions(cloudwatchMetricsService);
        assertThat(logging.events(), haveJourneyId(reference));
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
    void shouldErrorIfPayloadFailsToParse() {
        var malformedBodyPayload =
                new APIGatewayProxyRequestEvent()
                        .withHeaders(Map.of("Authorization", "Bearer " + BEARER_TOKEN))
                        .withBody("not-a-valid-delivery-receipt");

        var exception =
                assertThrows(
                        RuntimeException.class,
                        () -> handler.handleRequest(malformedBodyPayload, context),
                        "Expected to throw exception");

        verifyNoInteractions(cloudwatchMetricsService);
        assertThat(exception.getMessage(), equalTo("Unable to parse Notify Delivery Receipt"));
    }

    @Test
    void shouldParsePayloadWithExpectedNullValues() {
        assertDoesNotThrow(
                () -> {
                    when(configurationService.getNotificationTypeFromTemplateId(TEMPLATE_ID))
                            .thenReturn(Optional.of(VERIFY_PHONE_NUMBER));
                    var reference = UUID.randomUUID().toString();
                    var deliveryReceipt =
                            createDeliveryReceipt(
                                    reference,
                                    "+447316763843",
                                    "delivered",
                                    "sms",
                                    TEMPLATE_ID,
                                    new Date().toString(),
                                    null,
                                    null);
                    handler.handleRequest(eventWithBody(deliveryReceipt), context);
                    assertThat(logging.events(), haveJourneyId(reference));
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
                TEMPLATE_ID,
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
            String destination,
            String status,
            String notificationType,
            String templateID,
            String reference) {
        return createDeliveryReceipt(
                reference,
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
            String notificationType,
            String status,
            Instant createdAt,
            Instant completedAt,
            String reference) {
        return createDeliveryReceipt(
                reference,
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

    private void setupNotifyTemplate(Optional<DeliveryReceiptsNotificationType> maybeTemplate) {
        when(configurationService.getNotificationTypeFromTemplateId(TEMPLATE_ID))
                .thenReturn(maybeTemplate);
    }

    private Matcher<List<LogEvent>> haveJourneyId(String journeyId) {
        return new TypeSafeMatcher<>() {
            @Override
            protected boolean matchesSafely(List<LogEvent> items) {
                return items.stream()
                        .skip(1) // the first line will never have a journey id
                        .map(LogEvent::getContextData)
                        .map(item -> item.getValue("journeyId"))
                        .allMatch(journeyId::equals);
            }

            @Override
            public void describeTo(Description description) {
                description
                        .appendText(
                                "all but the first log events should have a context map with {journeyId=")
                        .appendValue(journeyId)
                        .appendText("}");
            }
        };
    }
}
