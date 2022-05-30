package uk.gov.di.authentication.deliveryreceiptsapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.authentication.deliveryreceiptsapi.entity.NotifyDeliveryReceipt;
import uk.gov.di.authentication.shared.helpers.IdGenerator;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.SerializationService;

import java.util.Collections;
import java.util.Date;
import java.util.Map;
import java.util.stream.Stream;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.deliveryreceiptsapi.entity.DeliveryMetricStatus.SMS_DELIVERED;
import static uk.gov.di.authentication.deliveryreceiptsapi.entity.DeliveryMetricStatus.SMS_FAILURE;
import static uk.gov.di.authentication.deliveryreceiptsapi.entity.DeliveryMetricStatus.SMS_UNDETERMINED;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class NotifyCallbackHandlerTest {

    private static final String BEARER_TOKEN = "1244656456457657566345";
    private static final String ENVIRONMENT = "test";
    private NotifyCallbackHandler handler;
    private final Context context = mock(Context.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final CloudwatchMetricsService cloudwatchMetricsService =
            mock(CloudwatchMetricsService.class);
    private final Json objectMapper = SerializationService.getInstance();

    @BeforeEach
    void setup() {
        when(configurationService.getNotifyCallbackBearerToken()).thenReturn(BEARER_TOKEN);
        when(configurationService.getEnvironment()).thenReturn(ENVIRONMENT);
        handler = new NotifyCallbackHandler(cloudwatchMetricsService, configurationService);
    }

    private static Stream<Arguments> phoneNumbers() {
        return Stream.of(
                Arguments.of("+447316763843", "44", "delivered", SMS_DELIVERED.toString()),
                Arguments.of("+4407316763843", "44", "delivered", SMS_DELIVERED.toString()),
                Arguments.of("+33645453322", "33", "delivered", SMS_DELIVERED.toString()),
                Arguments.of("+330645453322", "33", "delivered", SMS_DELIVERED.toString()),
                Arguments.of("+447316763843", "44", "delivered", SMS_DELIVERED.toString()),
                Arguments.of("+447316763843", "44", "delivered", SMS_DELIVERED.toString()),
                Arguments.of("+33645453322", "33", "delivered", SMS_DELIVERED.toString()),
                Arguments.of("+33645453322", "33", "delivered", SMS_DELIVERED.toString()),
                Arguments.of("07911123456", "44", "delivered", SMS_DELIVERED.toString()),
                Arguments.of("+447316763843", "44", "permanent-failure", SMS_FAILURE.toString()),
                Arguments.of("+4407316763843", "44", "permanent-failure", SMS_FAILURE.toString()),
                Arguments.of("+330645453322", "33", "technical-failure", SMS_FAILURE.toString()),
                Arguments.of("+33645453322", "33", "technical-failure", SMS_FAILURE.toString()),
                Arguments.of("07911123456", "44", "sent", SMS_UNDETERMINED.toString()),
                Arguments.of("+447316763843", "44", "sent", SMS_UNDETERMINED.toString()),
                Arguments.of("+4407316763843", "44", "sent", SMS_UNDETERMINED.toString()),
                Arguments.of("+330645453322", "33", "sent", SMS_UNDETERMINED.toString()),
                Arguments.of("+33645453322", "33", "sent", SMS_UNDETERMINED.toString()),
                Arguments.of("07911123456", "44", "sent", SMS_UNDETERMINED.toString()));
    }

    @ParameterizedTest
    @MethodSource("phoneNumbers")
    void shouldCallCloudwatchMetricServiceWhenSmsReceiptIsReceived(
            String number, String expectedCountryCode, String status, String counterName)
            throws Json.JsonException {
        var deliveryReceipt = createDeliveryReceipt(number, status, "sms");
        var event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("Authorization", "Bearer " + BEARER_TOKEN));
        event.setBody(objectMapper.writeValueAsString(deliveryReceipt));
        var response = handler.handleRequest(event, context);

        verify(cloudwatchMetricsService)
                .incrementCounter(
                        counterName,
                        Map.of(
                                "CountryCode",
                                expectedCountryCode,
                                "Environment",
                                ENVIRONMENT,
                                "NotifyStatus",
                                status));

        assertThat(response, hasStatus(204));
    }

    @Test
    void shouldNotCallCloudwatchMetricWithEmailNotificationType() throws Json.JsonException {
        var deliveryReceipt = createDeliveryReceipt("jim@test.com", "delivered", "email");
        var event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("Authorization", "Bearer " + BEARER_TOKEN));
        event.setBody(objectMapper.writeValueAsString(deliveryReceipt));
        handler.handleRequest(event, context);

        verifyNoInteractions(cloudwatchMetricsService);
    }

    @Test
    void shouldThrowIfBearerTokenIsMissing() {
        var event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Collections.emptyMap());

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

    private NotifyDeliveryReceipt createDeliveryReceipt(
            String destination, String status, String notificationType) {
        return new NotifyDeliveryReceipt(
                IdGenerator.generate(),
                null,
                destination,
                status,
                new Date().toString(),
                new Date().toString(),
                new Date().toString(),
                notificationType,
                IdGenerator.generate(),
                1);
    }
}
