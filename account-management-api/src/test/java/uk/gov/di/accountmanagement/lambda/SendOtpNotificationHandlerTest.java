package uk.gov.di.accountmanagement.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import software.amazon.awssdk.core.exception.SdkClientException;
import uk.gov.di.accountmanagement.entity.NotificationType;
import uk.gov.di.accountmanagement.entity.NotifyRequest;
import uk.gov.di.accountmanagement.services.AwsSqsClient;
import uk.gov.di.accountmanagement.services.CodeStorageService;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.services.CodeGeneratorService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.ValidationService;

import java.util.Map;
import java.util.Optional;

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.accountmanagement.entity.NotificationType.VERIFY_EMAIL;
import static uk.gov.di.authentication.shared.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;

class SendOtpNotificationHandlerTest {

    private static final String TEST_EMAIL_ADDRESS = "joe.bloggs@digital.cabinet-office.gov.uk";
    private static final String TEST_SIX_DIGIT_CODE = "123456";
    private static final long CODE_EXPIRY_TIME = 900;
    private final ValidationService validationService = mock(ValidationService.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final AwsSqsClient awsSqsClient = mock(AwsSqsClient.class);
    private final CodeGeneratorService codeGeneratorService = mock(CodeGeneratorService.class);
    private final CodeStorageService codeStorageService = mock(CodeStorageService.class);
    private final Context context = mock(Context.class);

    private final SendOtpNotificationHandler handler =
            new SendOtpNotificationHandler(
                    configurationService,
                    validationService,
                    awsSqsClient,
                    codeGeneratorService,
                    codeStorageService);

    @BeforeEach
    void setup() {
        when(configurationService.getCodeExpiry()).thenReturn(CODE_EXPIRY_TIME);
        when(codeGeneratorService.sixDigitCode()).thenReturn(TEST_SIX_DIGIT_CODE);
    }

    @Test
    void shouldReturn200AndPutMessageOnQueueForAValidRequest() throws JsonProcessingException {
        when(validationService.validateEmailAddress(eq(TEST_EMAIL_ADDRESS)))
                .thenReturn(Optional.empty());
        NotifyRequest notifyRequest =
                new NotifyRequest(TEST_EMAIL_ADDRESS, VERIFY_EMAIL, TEST_SIX_DIGIT_CODE);
        ObjectMapper objectMapper = new ObjectMapper();
        String serialisedRequest = objectMapper.writeValueAsString(notifyRequest);

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of());
        event.setBody(
                format(
                        "{ \"email\": \"%s\", \"notificationType\": \"%s\" }",
                        TEST_EMAIL_ADDRESS, VERIFY_EMAIL));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertEquals(200, result.getStatusCode());

        verify(awsSqsClient).send(serialisedRequest);
        verify(codeStorageService)
                .saveOtpCode(
                        TEST_EMAIL_ADDRESS, TEST_SIX_DIGIT_CODE, CODE_EXPIRY_TIME, VERIFY_EMAIL);
    }

    @Test
    public void shouldReturn400IfRequestIsMissingEmail() {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of());
        event.setBody("{ }");
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertEquals(400, result.getStatusCode());
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1001));
    }

    @Test
    public void shouldReturn400IfEmailAddressIsInvalid() {

        when(validationService.validateEmailAddress(eq("joe.bloggs")))
                .thenReturn(Optional.of(ErrorResponse.ERROR_1004));

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of());
        event.setBody(
                format(
                        "{ \"email\": \"%s\", \"notificationType\": \"%s\" }",
                        "joe.bloggs", VERIFY_EMAIL));

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertEquals(400, result.getStatusCode());
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1004));
    }

    @Test
    public void shouldReturn500IfMessageCannotBeSentToQueue() throws JsonProcessingException {
        when(validationService.validateEmailAddress(eq(TEST_EMAIL_ADDRESS)))
                .thenReturn(Optional.empty());
        NotifyRequest notifyRequest =
                new NotifyRequest(TEST_EMAIL_ADDRESS, VERIFY_EMAIL, TEST_SIX_DIGIT_CODE);
        ObjectMapper objectMapper = new ObjectMapper();
        String serialisedRequest = objectMapper.writeValueAsString(notifyRequest);
        Mockito.doThrow(SdkClientException.class).when(awsSqsClient).send(eq(serialisedRequest));

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of());
        event.setBody(
                format(
                        "{ \"email\": \"%s\", \"notificationType\": \"%s\" }",
                        TEST_EMAIL_ADDRESS, VERIFY_EMAIL));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertEquals(500, result.getStatusCode());
        assertTrue(result.getBody().contains("Error sending message to queue"));
    }

    @Test
    public void shouldReturn400WhenInvalidNotificationType() {
        when(validationService.validateEmailAddress(eq(TEST_EMAIL_ADDRESS)))
                .thenReturn(Optional.empty());

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of());
        event.setBody(
                format(
                        "{ \"email\": \"%s\", \"notificationType\": \"%s\" }",
                        TEST_EMAIL_ADDRESS, "VERIFY_PASSWORD"));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertEquals(400, result.getStatusCode());
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1001));

        verify(awsSqsClient, never()).send(anyString());
        verify(codeStorageService, never())
                .saveOtpCode(anyString(), anyString(), anyLong(), any(NotificationType.class));
    }
}
