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
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.accountmanagement.entity.NotificationType.EMAIL_UPDATED;
import static uk.gov.di.accountmanagement.entity.NotificationType.VERIFY_EMAIL;
import static uk.gov.di.authentication.shared.matchers.APIGatewayProxyResponseEventMatcher.hasBody;
import static uk.gov.di.authentication.shared.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.authentication.shared.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class UpdateEmailHandlerTest {

    private final Context context = mock(Context.class);
    private final DynamoService dynamoService = mock(DynamoService.class);
    private final AwsSqsClient sqsClient = mock(AwsSqsClient.class);
    private final ValidationService validationService = mock(ValidationService.class);
    private final CodeStorageService codeStorageService = mock(CodeStorageService.class);
    private UpdateEmailHandler handler;
    private static final String EXISTING_EMAIL_ADDRESS = "joe.bloggs@digital.cabinet-office.gov.uk";
    private static final String NEW_EMAIL_ADDRESS = "bloggs.joe@digital.cabinet-office.gov.uk";
    private static final String INVALID_EMAIL_ADDRESS = "igital.cabinet-office.gov.uk";
    private static final String OTP = "123456";
    private static final Subject SUBJECT = new Subject();

    @BeforeEach
    public void setUp() {
        handler =
                new UpdateEmailHandler(
                        dynamoService, sqsClient, validationService, codeStorageService);
    }

    @Test
    public void shouldReturn204ForValidUpdateEmailRequest() throws JsonProcessingException {
        UserProfile userProfile = new UserProfile().setPublicSubjectID(SUBJECT.getValue());
        when(dynamoService.getUserProfileByEmail(EXISTING_EMAIL_ADDRESS)).thenReturn(userProfile);
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody(
                format(
                        "{\"existingEmailAddress\": \"%s\", \"replacementEmailAddress\": \"%s\", \"otp\": \"%s\"  }",
                        EXISTING_EMAIL_ADDRESS, NEW_EMAIL_ADDRESS, OTP));
        APIGatewayProxyRequestEvent.ProxyRequestContext proxyRequestContext =
                new APIGatewayProxyRequestEvent.ProxyRequestContext();
        Map<String, Object> authorizerParams = new HashMap<>();
        authorizerParams.put("principalId", SUBJECT.getValue());
        proxyRequestContext.setAuthorizer(authorizerParams);
        event.setRequestContext(proxyRequestContext);
        when(codeStorageService.isValidOtpCode(NEW_EMAIL_ADDRESS, OTP, VERIFY_EMAIL))
                .thenReturn(true);
        when(validationService.validateEmailAddressUpdate(
                        EXISTING_EMAIL_ADDRESS, NEW_EMAIL_ADDRESS))
                .thenReturn(Optional.empty());

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(204));
        verify(dynamoService).updateEmail(EXISTING_EMAIL_ADDRESS, NEW_EMAIL_ADDRESS);
        NotifyRequest notifyRequest = new NotifyRequest(NEW_EMAIL_ADDRESS, EMAIL_UPDATED);
        verify(sqsClient).send(new ObjectMapper().writeValueAsString(notifyRequest));
    }

    @Test
    public void shouldReturn400WhenReplacementEmailAlreadyExists() throws JsonProcessingException {
        when(dynamoService.getSubjectFromEmail(EXISTING_EMAIL_ADDRESS)).thenReturn(SUBJECT);
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody(
                format(
                        "{\"existingEmailAddress\": \"%s\", \"replacementEmailAddress\": \"%s\", \"otp\": \"%s\"  }",
                        EXISTING_EMAIL_ADDRESS, NEW_EMAIL_ADDRESS, OTP));
        APIGatewayProxyRequestEvent.ProxyRequestContext proxyRequestContext =
                new APIGatewayProxyRequestEvent.ProxyRequestContext();
        Map<String, Object> authorizerParams = new HashMap<>();
        authorizerParams.put("principalId", SUBJECT.getValue());
        proxyRequestContext.setAuthorizer(authorizerParams);
        event.setRequestContext(proxyRequestContext);
        when(codeStorageService.isValidOtpCode(NEW_EMAIL_ADDRESS, OTP, VERIFY_EMAIL))
                .thenReturn(true);
        when(validationService.validateEmailAddressUpdate(
                        EXISTING_EMAIL_ADDRESS, NEW_EMAIL_ADDRESS))
                .thenReturn(Optional.empty());
        when(dynamoService.userExists(NEW_EMAIL_ADDRESS)).thenReturn(true);
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        verify(dynamoService, never()).updateEmail(EXISTING_EMAIL_ADDRESS, NEW_EMAIL_ADDRESS);
        NotifyRequest notifyRequest = new NotifyRequest(NEW_EMAIL_ADDRESS, EMAIL_UPDATED);
        verify(sqsClient, never()).send(new ObjectMapper().writeValueAsString(notifyRequest));
        String expectedResponse = new ObjectMapper().writeValueAsString(ErrorResponse.ERROR_1009);
        assertThat(result, hasBody(expectedResponse));
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
        event.setBody(format("{\"existingEmailAddress\": \"%s\"}", EXISTING_EMAIL_ADDRESS));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1001));
    }

    @Test
    public void shouldReturnErrorWhenOtpCodeIsNotValid() throws JsonProcessingException {
        when(dynamoService.getSubjectFromEmail(EXISTING_EMAIL_ADDRESS)).thenReturn(SUBJECT);
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody(
                format(
                        "{\"existingEmailAddress\": \"%s\", \"replacementEmailAddress\": \"%s\", \"otp\": \"%s\"  }",
                        EXISTING_EMAIL_ADDRESS, INVALID_EMAIL_ADDRESS, OTP));
        APIGatewayProxyRequestEvent.ProxyRequestContext proxyRequestContext =
                new APIGatewayProxyRequestEvent.ProxyRequestContext();
        Map<String, Object> authorizerParams = new HashMap<>();
        authorizerParams.put("principalId", SUBJECT.getValue());
        proxyRequestContext.setAuthorizer(authorizerParams);
        event.setRequestContext(proxyRequestContext);
        when(codeStorageService.isValidOtpCode(INVALID_EMAIL_ADDRESS, OTP, VERIFY_EMAIL))
                .thenReturn(false);
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        verify(dynamoService, never()).updateEmail(EXISTING_EMAIL_ADDRESS, INVALID_EMAIL_ADDRESS);
        NotifyRequest notifyRequest = new NotifyRequest(INVALID_EMAIL_ADDRESS, EMAIL_UPDATED);
        verify(sqsClient, never()).send(new ObjectMapper().writeValueAsString(notifyRequest));
        String expectedResponse = new ObjectMapper().writeValueAsString(ErrorResponse.ERROR_1020);
        assertThat(result, hasBody(expectedResponse));
    }

    @Test
    public void shouldReturn400AndNotUpdateEmailWhenEmailIsInvalid()
            throws JsonProcessingException {
        when(dynamoService.getSubjectFromEmail(EXISTING_EMAIL_ADDRESS)).thenReturn(SUBJECT);
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody(
                format(
                        "{\"existingEmailAddress\": \"%s\", \"replacementEmailAddress\": \"%s\", \"otp\": \"%s\"  }",
                        EXISTING_EMAIL_ADDRESS, INVALID_EMAIL_ADDRESS, OTP));
        APIGatewayProxyRequestEvent.ProxyRequestContext proxyRequestContext =
                new APIGatewayProxyRequestEvent.ProxyRequestContext();
        Map<String, Object> authorizerParams = new HashMap<>();
        authorizerParams.put("principalId", SUBJECT.getValue());
        proxyRequestContext.setAuthorizer(authorizerParams);
        event.setRequestContext(proxyRequestContext);
        when(codeStorageService.isValidOtpCode(INVALID_EMAIL_ADDRESS, OTP, VERIFY_EMAIL))
                .thenReturn(true);
        when(validationService.validateEmailAddressUpdate(
                        EXISTING_EMAIL_ADDRESS, INVALID_EMAIL_ADDRESS))
                .thenReturn(Optional.of(ErrorResponse.ERROR_1004));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        verify(dynamoService, never()).updateEmail(EXISTING_EMAIL_ADDRESS, INVALID_EMAIL_ADDRESS);
        NotifyRequest notifyRequest = new NotifyRequest(INVALID_EMAIL_ADDRESS, EMAIL_UPDATED);
        verify(sqsClient, never()).send(new ObjectMapper().writeValueAsString(notifyRequest));
        String expectedResponse = new ObjectMapper().writeValueAsString(ErrorResponse.ERROR_1004);
        assertThat(result, hasBody(expectedResponse));
    }
}
