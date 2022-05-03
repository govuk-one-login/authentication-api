package uk.gov.di.accountmanagement.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.accountmanagement.domain.AccountManagementAuditableEvent;
import uk.gov.di.accountmanagement.entity.NotifyRequest;
import uk.gov.di.accountmanagement.services.AwsSqsClient;
import uk.gov.di.accountmanagement.services.CodeStorageService;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.helpers.ObjectMapperFactory;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.DynamoService;

import java.util.HashMap;
import java.util.Map;

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.di.accountmanagement.entity.NotificationType.PHONE_NUMBER_UPDATED;
import static uk.gov.di.accountmanagement.entity.NotificationType.VERIFY_PHONE_NUMBER;
import static uk.gov.di.authentication.sharedtest.helper.RequestEventHelper.identityWithSourceIp;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class UpdatePhoneNumberHandlerTest {

    private final Context context = mock(Context.class);
    private final DynamoService dynamoService = mock(DynamoService.class);
    private final AwsSqsClient sqsClient = mock(AwsSqsClient.class);
    private final CodeStorageService codeStorageService = mock(CodeStorageService.class);
    private UpdatePhoneNumberHandler handler;
    private static final String EMAIL_ADDRESS = "joe.bloggs@digital.cabinet-office.gov.uk";
    private static final String NEW_PHONE_NUMBER = "07755551084";
    private static final String OLD_PHONE_NUMBER = "09876543219";
    private static final String INVALID_PHONE_NUMBER = "12345";
    private static final String OTP = "123456";
    private static final Subject SUBJECT = new Subject();
    private static final ObjectMapper objectMapper = ObjectMapperFactory.getInstance();

    private final AuditService auditService = mock(AuditService.class);

    @BeforeEach
    public void setUp() {
        handler =
                new UpdatePhoneNumberHandler(
                        dynamoService, sqsClient, codeStorageService, auditService);
    }

    @Test
    public void shouldReturn204ForValidUpdatePhoneNumberRequest() throws JsonProcessingException {
        String persistentIdValue = "some-persistent-session-id";
        UserProfile userProfile =
                new UserProfile()
                        .setPublicSubjectID(SUBJECT.getValue())
                        .setPhoneNumber(OLD_PHONE_NUMBER);
        when(dynamoService.getUserProfileByEmail(EMAIL_ADDRESS)).thenReturn(userProfile);
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody(
                format(
                        "{\"email\": \"%s\", \"phoneNumber\": \"%s\", \"otp\": \"%s\"  }",
                        EMAIL_ADDRESS, NEW_PHONE_NUMBER, OTP));
        event.setHeaders(Map.of(PersistentIdHelper.PERSISTENT_ID_HEADER_NAME, persistentIdValue));
        APIGatewayProxyRequestEvent.ProxyRequestContext proxyRequestContext =
                new APIGatewayProxyRequestEvent.ProxyRequestContext();
        Map<String, Object> authorizerParams = new HashMap<>();
        authorizerParams.put("principalId", SUBJECT.getValue());
        proxyRequestContext.setIdentity(identityWithSourceIp("123.123.123.123"));
        proxyRequestContext.setAuthorizer(authorizerParams);
        event.setRequestContext(proxyRequestContext);
        when(codeStorageService.isValidOtpCode(EMAIL_ADDRESS, OTP, VERIFY_PHONE_NUMBER))
                .thenReturn(true);

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(204));
        verify(dynamoService).updatePhoneNumber(EMAIL_ADDRESS, NEW_PHONE_NUMBER);
        NotifyRequest notifyRequest = new NotifyRequest(EMAIL_ADDRESS, PHONE_NUMBER_UPDATED);
        verify(sqsClient).send(objectMapper.writeValueAsString(notifyRequest));

        verify(auditService)
                .submitAuditEvent(
                        AccountManagementAuditableEvent.UPDATE_PHONE_NUMBER,
                        context.getAwsRequestId(),
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        userProfile.getSubjectID(),
                        userProfile.getEmail(),
                        "123.123.123.123",
                        NEW_PHONE_NUMBER,
                        persistentIdValue);
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

        verifyNoInteractions(auditService);
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
        verify(sqsClient, times(0)).send(objectMapper.writeValueAsString(notifyRequest));
        String expectedResponse = objectMapper.writeValueAsString(ErrorResponse.ERROR_1020);
        assertThat(result, hasBody(expectedResponse));
        verifyNoInteractions(auditService);
    }
}
