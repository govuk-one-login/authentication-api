package uk.gov.di.accountmanagement.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.accountmanagement.entity.NotifyRequest;
import uk.gov.di.accountmanagement.services.AwsSqsClient;
import uk.gov.di.accountmanagement.services.CodeStorageService;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.ValidationService;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.accountmanagement.entity.NotificationType.PHONE_NUMBER_UPDATED;
import static uk.gov.di.accountmanagement.entity.NotificationType.VERIFY_PHONE_NUMBER;
import static uk.gov.di.authentication.shared.matchers.APIGatewayProxyResponseEventMatcher.hasBody;
import static uk.gov.di.authentication.shared.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.authentication.shared.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class UpdatePhoneNumberHandlerTest {

    private final Context context = mock(Context.class);
    private final DynamoService dynamoService = mock(DynamoService.class);
    private final AwsSqsClient sqsClient = mock(AwsSqsClient.class);
    private final ValidationService validationService = mock(ValidationService.class);
    private final CodeStorageService codeStorageService = mock(CodeStorageService.class);
    private UpdatePhoneNumberHandler handler;
    private static final String EMAIL_ADDRESS = "joe.bloggs@digital.cabinet-office.gov.uk";
    private static final String PHONE_NUMBER = "01234567891";
    private static final String INVALID_PHONE_NUMBER = "12345";
    private static final String OTP = "123456";
    private static final Subject SUBJECT = new Subject();

    @BeforeEach
    public void setUp() {
        handler =
                new UpdatePhoneNumberHandler(
                        dynamoService, sqsClient, validationService, codeStorageService);
    }

    @Test
    public void shouldReturn200ForValidUpdatePhoneNumberRequest() throws JsonProcessingException {
        UserProfile userProfile = new UserProfile().setPublicSubjectID(SUBJECT.getValue());
        when(dynamoService.getUserProfileByEmail(EMAIL_ADDRESS)).thenReturn(userProfile);
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody(
                format(
                        "{\"email\": \"%s\", \"phoneNumber\": \"%s\", \"otp\": \"%s\"  }",
                        EMAIL_ADDRESS, PHONE_NUMBER, OTP));
        APIGatewayProxyRequestEvent.ProxyRequestContext proxyRequestContext =
                new APIGatewayProxyRequestEvent.ProxyRequestContext();
        Map<String, Object> authorizerParams = new HashMap<>();
        authorizerParams.put("principalId", SUBJECT.getValue());
        proxyRequestContext.setAuthorizer(authorizerParams);
        event.setRequestContext(proxyRequestContext);
        when(codeStorageService.isValidOtpCode(EMAIL_ADDRESS, OTP, VERIFY_PHONE_NUMBER))
                .thenReturn(true);
        when(validationService.validatePhoneNumber(PHONE_NUMBER)).thenReturn(Optional.empty());

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(200));
        verify(dynamoService).updatePhoneNumber(EMAIL_ADDRESS, PHONE_NUMBER);
        NotifyRequest notifyRequest = new NotifyRequest(EMAIL_ADDRESS, PHONE_NUMBER_UPDATED);
        verify(sqsClient).send(new ObjectMapper().writeValueAsString(notifyRequest));
    }

    @Test
    public void shouldReturn400WhenRequestIsMissingParameters() {
        APIGatewayProxyRequestEvent.ProxyRequestContext proxyRequestContext =
                new APIGatewayProxyRequestEvent.ProxyRequestContext();
        Map<String, Object> authorizerParams = new HashMap<>();
        authorizerParams.put("principalId", SUBJECT.getValue());
        proxyRequestContext.setAuthorizer(authorizerParams);
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setRequestContext(proxyRequestContext);
        event.setBody(format("{\"email\": \"%s\"}", EMAIL_ADDRESS));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1001));
    }

    @Test
    public void shouldReturnErrorWhenOtpCodeIsNotValid() throws JsonProcessingException {
        when(dynamoService.getSubjectFromEmail(EMAIL_ADDRESS)).thenReturn(SUBJECT);
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody(
                format(
                        "{\"email\": \"%s\", \"phoneNumber\": \"%s\", \"otp\": \"%s\"  }",
                        EMAIL_ADDRESS, INVALID_PHONE_NUMBER, OTP));
        APIGatewayProxyRequestEvent.ProxyRequestContext proxyRequestContext =
                new APIGatewayProxyRequestEvent.ProxyRequestContext();
        Map<String, Object> authorizerParams = new HashMap<>();
        authorizerParams.put("principalId", SUBJECT.getValue());
        proxyRequestContext.setAuthorizer(authorizerParams);
        event.setRequestContext(proxyRequestContext);
        when(codeStorageService.isValidOtpCode(EMAIL_ADDRESS, OTP, VERIFY_PHONE_NUMBER))
                .thenReturn(false);
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        verify(dynamoService, times(0)).updatePhoneNumber(EMAIL_ADDRESS, INVALID_PHONE_NUMBER);
        NotifyRequest notifyRequest = new NotifyRequest(INVALID_PHONE_NUMBER, PHONE_NUMBER_UPDATED);
        verify(sqsClient, times(0)).send(new ObjectMapper().writeValueAsString(notifyRequest));
        String expectedResponse = new ObjectMapper().writeValueAsString(ErrorResponse.ERROR_1020);
        assertThat(result, hasBody(expectedResponse));
    }

    @Test
    public void shouldReturn400AndNotUpdatePhoneNumberWhenPhoneNumberIsInvalid()
            throws JsonProcessingException {
        when(dynamoService.getSubjectFromEmail(EMAIL_ADDRESS)).thenReturn(SUBJECT);
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody(
                format(
                        "{\"email\": \"%s\", \"phoneNumber\": \"%s\", \"otp\": \"%s\"  }",
                        EMAIL_ADDRESS, INVALID_PHONE_NUMBER, OTP));
        APIGatewayProxyRequestEvent.ProxyRequestContext proxyRequestContext =
                new APIGatewayProxyRequestEvent.ProxyRequestContext();
        Map<String, Object> authorizerParams = new HashMap<>();
        authorizerParams.put("principalId", SUBJECT.getValue());
        proxyRequestContext.setAuthorizer(authorizerParams);
        event.setRequestContext(proxyRequestContext);
        when(codeStorageService.isValidOtpCode(EMAIL_ADDRESS, OTP, VERIFY_PHONE_NUMBER))
                .thenReturn(true);
        when(validationService.validatePhoneNumber(INVALID_PHONE_NUMBER))
                .thenReturn(Optional.of(ErrorResponse.ERROR_1012));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        verify(dynamoService, times(0)).updatePhoneNumber(EMAIL_ADDRESS, INVALID_PHONE_NUMBER);
        NotifyRequest notifyRequest = new NotifyRequest(INVALID_PHONE_NUMBER, PHONE_NUMBER_UPDATED);
        verify(sqsClient, times(0)).send(new ObjectMapper().writeValueAsString(notifyRequest));
        String expectedResponse = new ObjectMapper().writeValueAsString(ErrorResponse.ERROR_1012);
        assertThat(result, hasBody(expectedResponse));
    }
}
