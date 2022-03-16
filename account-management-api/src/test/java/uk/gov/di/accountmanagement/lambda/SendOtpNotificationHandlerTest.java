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
import uk.gov.di.accountmanagement.domain.AccountManagementAuditableEvent;
import uk.gov.di.accountmanagement.entity.NotificationType;
import uk.gov.di.accountmanagement.entity.NotifyRequest;
import uk.gov.di.accountmanagement.services.AwsSqsClient;
import uk.gov.di.accountmanagement.services.CodeStorageService;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.CodeGeneratorService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;
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
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.di.accountmanagement.entity.NotificationType.VERIFY_EMAIL;
import static uk.gov.di.accountmanagement.entity.NotificationType.VERIFY_PHONE_NUMBER;
import static uk.gov.di.authentication.shared.services.AuditService.MetadataPair.pair;
import static uk.gov.di.authentication.sharedtest.helper.RequestEventHelper.contextWithSourceIp;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;

class SendOtpNotificationHandlerTest {

    private static final String TEST_EMAIL_ADDRESS = "joe.bloggs@digital.cabinet-office.gov.uk";
    private static final String TEST_SIX_DIGIT_CODE = "123456";
    private static final String TEST_PHONE_NUMBER = "07755551084";
    private static final long CODE_EXPIRY_TIME = 900;
    private final ValidationService validationService = mock(ValidationService.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final AwsSqsClient awsSqsClient = mock(AwsSqsClient.class);
    private final CodeGeneratorService codeGeneratorService = mock(CodeGeneratorService.class);
    private final CodeStorageService codeStorageService = mock(CodeStorageService.class);
    private final DynamoService dynamoService = mock(DynamoService.class);
    private final Context context = mock(Context.class);
    private final AuditService auditService = mock(AuditService.class);

    private final SendOtpNotificationHandler handler =
            new SendOtpNotificationHandler(
                    configurationService,
                    validationService,
                    awsSqsClient,
                    codeGeneratorService,
                    codeStorageService,
                    dynamoService,
                    auditService);

    @BeforeEach
    void setup() {
        when(configurationService.getCodeExpiry()).thenReturn(CODE_EXPIRY_TIME);
        when(codeGeneratorService.sixDigitCode()).thenReturn(TEST_SIX_DIGIT_CODE);
    }

    @Test
    void shouldReturn204AndPutMessageOnQueueForAValidEmailRequest() throws JsonProcessingException {
        String persistentIdValue = "some-persistent-session-id";
        when(validationService.validateEmailAddress(eq(TEST_EMAIL_ADDRESS)))
                .thenReturn(Optional.empty());
        NotifyRequest notifyRequest =
                new NotifyRequest(TEST_EMAIL_ADDRESS, VERIFY_EMAIL, TEST_SIX_DIGIT_CODE);
        ObjectMapper objectMapper = new ObjectMapper();
        String serialisedRequest = objectMapper.writeValueAsString(notifyRequest);

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of(PersistentIdHelper.PERSISTENT_ID_HEADER_NAME, persistentIdValue));
        event.setRequestContext(contextWithSourceIp("123.123.123.123"));
        event.setBody(
                format(
                        "{ \"email\": \"%s\", \"notificationType\": \"%s\" }",
                        TEST_EMAIL_ADDRESS, VERIFY_EMAIL));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertEquals(204, result.getStatusCode());

        verify(awsSqsClient).send(serialisedRequest);
        verify(codeStorageService)
                .saveOtpCode(
                        TEST_EMAIL_ADDRESS, TEST_SIX_DIGIT_CODE, CODE_EXPIRY_TIME, VERIFY_EMAIL);

        verify(auditService)
                .submitAuditEvent(
                        AccountManagementAuditableEvent.SEND_OTP,
                        context.getAwsRequestId(),
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        TEST_EMAIL_ADDRESS,
                        "123.123.123.123",
                        null,
                        persistentIdValue,
                        pair("notification-type", VERIFY_EMAIL));
    }

    @Test
    void shouldReturn204AndPutMessageOnQueueForAValidPhoneRequest() throws JsonProcessingException {
        NotifyRequest notifyRequest =
                new NotifyRequest(TEST_PHONE_NUMBER, VERIFY_PHONE_NUMBER, TEST_SIX_DIGIT_CODE);
        ObjectMapper objectMapper = new ObjectMapper();
        String serialisedRequest = objectMapper.writeValueAsString(notifyRequest);

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of());
        event.setRequestContext(contextWithSourceIp("123.123.123.123"));
        event.setBody(
                format(
                        "{ \"email\": \"%s\", \"notificationType\": \"%s\", \"phoneNumber\": \"%s\"  }",
                        TEST_EMAIL_ADDRESS, VERIFY_PHONE_NUMBER, TEST_PHONE_NUMBER));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertEquals(204, result.getStatusCode());

        verify(awsSqsClient).send(serialisedRequest);
        verify(codeStorageService)
                .saveOtpCode(
                        TEST_EMAIL_ADDRESS,
                        TEST_SIX_DIGIT_CODE,
                        CODE_EXPIRY_TIME,
                        VERIFY_PHONE_NUMBER);

        verify(auditService)
                .submitAuditEvent(
                        AccountManagementAuditableEvent.SEND_OTP,
                        context.getAwsRequestId(),
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        TEST_EMAIL_ADDRESS,
                        "123.123.123.123",
                        TEST_PHONE_NUMBER,
                        PersistentIdHelper.PERSISTENT_ID_UNKNOWN_VALUE,
                        pair("notification-type", VERIFY_PHONE_NUMBER));
    }

    @Test
    public void shouldReturn400IfRequestIsMissingEmail() {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of());
        event.setBody("{ }");
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertEquals(400, result.getStatusCode());
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1001));

        verifyNoInteractions(auditService);
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

        verifyNoInteractions(auditService);
    }

    @Test
    public void shouldReturn400IfPhoneNumberIsInvalid() {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of());
        event.setBody(
                format(
                        "{ \"email\": \"%s\", \"notificationType\": \"%s\", \"phoneNumber\": \"%s\" }",
                        TEST_EMAIL_ADDRESS, VERIFY_PHONE_NUMBER, "12345"));

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertEquals(400, result.getStatusCode());
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1012));

        verifyNoInteractions(auditService);
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

        verifyNoInteractions(auditService);
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

        verifyNoInteractions(auditService);
    }

    @Test
    public void shouldReturn400WhenAccountAlreadyExistsWithGivenEmail() {
        when(validationService.validateEmailAddress(eq(TEST_EMAIL_ADDRESS)))
                .thenReturn(Optional.empty());
        when(dynamoService.userExists(eq(TEST_EMAIL_ADDRESS))).thenReturn(true);

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of());
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
