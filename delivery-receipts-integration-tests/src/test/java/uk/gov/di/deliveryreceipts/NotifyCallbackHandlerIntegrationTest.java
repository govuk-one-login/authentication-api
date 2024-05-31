package uk.gov.di.deliveryreceipts;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.authentication.deliveryreceiptsapi.entity.NotifyDeliveryReceipt;
import uk.gov.di.authentication.deliveryreceiptsapi.lambda.NotifyCallbackHandler;
import uk.gov.di.authentication.shared.entity.BulkEmailStatus;
import uk.gov.di.authentication.shared.entity.BulkEmailUser;
import uk.gov.di.authentication.shared.helpers.IdGenerator;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.BulkEmailUsersService;
import uk.gov.di.authentication.shared.services.SerializationService;
import uk.gov.di.authentication.shared.services.SystemService;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;
import uk.gov.di.authentication.sharedtest.extensions.BulkEmailUsersExtension;

import java.util.Date;
import java.util.Map;
import java.util.UUID;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.mockito.Mockito.mock;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class NotifyCallbackHandlerIntegrationTest extends ApiGatewayHandlerIntegrationTest {
    private static final String BEARER_TOKEN = "notify-test-@bearer-token";
    private static final Json objectMapper = SerializationService.getInstance();
    private static final String EMAIL_SENT_TEMPLATE_ID = "35454-543543-3435435-12340";
    private static final String VERIFY_PHONE_NUMBER_TEMPLATE_ID = "35454-543543-3435435-12348";

    private static final String TERMS_AND_CONDITIONS_BULK_EMAIL_TEMPLATE_ID =
            "35454-543543-3435435-12450";

    private final Context context = mock(Context.class);
    private NotifyCallbackHandler handler;

    private static final IntegrationTestConfigurationService CONFIGURATION_SERVICE =
            new IntegrationTestConfigurationService(
                    notificationsQueue,
                    tokenSigner,
                    docAppPrivateKeyJwtSigner,
                    configurationParameters,
                    new SystemService()) {
                @Override
                public boolean isBulkUserEmailEnabled() {
                    return true;
                }
            };

    @RegisterExtension
    protected static final BulkEmailUsersExtension bulkEmailUsersExtension =
            new BulkEmailUsersExtension();

    protected final BulkEmailUsersService bulkEmailUsersService =
            new BulkEmailUsersService(CONFIGURATION_SERVICE);

    @BeforeEach
    void setup() {
        CONFIGURATION_SERVICE.setSystemService(new SystemService());
        handler = new NotifyCallbackHandler(CONFIGURATION_SERVICE);
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

    @Test
    void shouldUpdateBulkUserDeliveryStatusWhenTermsAndConditionsEmailReceived() {
        String email = "joe.bloggs@digital.cabinet-office.gov.uk";
        String subjectId = "subject-1";
        bulkEmailUsersExtension.addBulkEmailUser(subjectId, BulkEmailStatus.EMAIL_SENT);
        userStore.signUp(email, "password-1", new Subject(subjectId));

        var response =
                makeRequest(
                        new NotifyDeliveryReceipt(
                                IdGenerator.generate(),
                                null,
                                email,
                                "delivered",
                                new Date().toString(),
                                new Date().toString(),
                                new Date().toString(),
                                "email",
                                TERMS_AND_CONDITIONS_BULK_EMAIL_TEMPLATE_ID,
                                1),
                        Map.of("Authorization", "Bearer " + BEARER_TOKEN));

        assertThat(response, hasStatus(204));
        BulkEmailUser bulkEmailUserAfterUpdate =
                bulkEmailUsersService.getBulkEmailUsers(subjectId).get();
        assertThat(bulkEmailUserAfterUpdate.getDeliveryReceiptStatus(), equalTo("delivered"));
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
