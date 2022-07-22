package uk.gov.di.deliveryreceipts;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.authentication.deliveryreceiptsapi.entity.NotifyDeliveryReceipt;
import uk.gov.di.authentication.deliveryreceiptsapi.lambda.NotifyCallbackHandler;
import uk.gov.di.authentication.shared.helpers.IdGenerator;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.SerializationService;
import uk.gov.di.authentication.sharedtest.extensions.ParameterStoreExtension;

import java.util.Date;
import java.util.Map;
import java.util.UUID;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.mock;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

public class NotifyCallbackHandlerIntegrationTest {

    private static final String BEARER_TOKEN = "notify-test-@bearer-token";
    private static final Json objectMapper = SerializationService.getInstance();
    private static final String EMAIL_SENT_TEMPLATE_ID = "35454-543543-3435435-12340";
    private static final String VERIFY_PHONE_NUMBER_TEMPLATE_ID = "35454-543543-3435435-12348";

    private final Context context = mock(Context.class);
    private NotifyCallbackHandler handler;

    @RegisterExtension
    private static final ParameterStoreExtension configurationParameters =
            new ParameterStoreExtension(Map.of("local-notify-callback-bearer-token", BEARER_TOKEN));

    @BeforeEach
    void setup() {
        handler = new NotifyCallbackHandler(new ConfigurationService());
    }

    @Test
    void shouldAddToCloudwatchWhenSmsDeliveryReceiptIsReceived() {
        var response =
                makeRequest(
                        new NotifyDeliveryReceipt(
                                IdGenerator.generate(),
                                null,
                                "+447316763843",
                                "delivered",
                                new Date().toString(),
                                new Date().toString(),
                                new Date().toString(),
                                "sms",
                                VERIFY_PHONE_NUMBER_TEMPLATE_ID,
                                1),
                        Map.of("Authorization", "Bearer " + BEARER_TOKEN));

        assertThat(response, hasStatus(204));
    }

    @Test
    void shouldAddToCloudwatchWhenEmailDeliveryReceiptIsReceived() {
        var response =
                makeRequest(
                        new NotifyDeliveryReceipt(
                                IdGenerator.generate(),
                                null,
                                "joe.bloggs@digital.cabinet-office.gov.uk",
                                "delivered",
                                new Date().toString(),
                                new Date().toString(),
                                new Date().toString(),
                                "email",
                                EMAIL_SENT_TEMPLATE_ID,
                                1),
                        Map.of("Authorization", "Bearer " + BEARER_TOKEN));

        assertThat(response, hasStatus(204));
    }

    private APIGatewayProxyResponseEvent makeRequest(
            NotifyDeliveryReceipt body, Map<String, String> headers) {
        var request = new APIGatewayProxyRequestEvent();
        request.withHeaders(headers)
                .withRequestContext(
                        new APIGatewayProxyRequestEvent.ProxyRequestContext()
                                .withRequestId(UUID.randomUUID().toString()));

        try {
            request.withBody(objectMapper.writeValueAsString(body));
        } catch (Json.JsonException e) {
            throw new RuntimeException("Could not serialise test body", e);
        }
        return handler.handleRequest(request, context);
    }
}
