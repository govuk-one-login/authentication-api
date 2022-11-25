package uk.gov.di.accountmanagement.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.accountmanagement.domain.AccountManagementAuditableEvent;
import uk.gov.di.accountmanagement.entity.NotifyRequest;
import uk.gov.di.accountmanagement.services.AwsSqsClient;
import uk.gov.di.accountmanagement.services.CodeStorageService;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.helpers.LocaleHelper.SupportedLanguage;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.SerializationService;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

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
    private static final String OTP = "123456";
    private static final Subject PUBLIC_SUBJECT = new Subject();
    private static final String PERSISTENT_ID = "some-persistent-session-id";

    private final Json objectMapper = SerializationService.getInstance();
    private final AuditService auditService = mock(AuditService.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);

    @BeforeEach
    void setUp() {
        handler =
                new UpdatePhoneNumberHandler(
                        dynamoService,
                        sqsClient,
                        codeStorageService,
                        auditService,
                        configurationService);
    }

    @Test
    void shouldReturn204ForValidUpdatePhoneNumberRequest() throws Json.JsonException {
        when(codeStorageService.isValidOtpCode(EMAIL_ADDRESS, OTP, VERIFY_PHONE_NUMBER))
                .thenReturn(true);
        var userProfile =
                new UserProfile()
                        .withPublicSubjectID(PUBLIC_SUBJECT.getValue())
                        .withPhoneNumber(OLD_PHONE_NUMBER);
        when(dynamoService.getUserProfileByEmailMaybe(EMAIL_ADDRESS))
                .thenReturn(Optional.of(userProfile));

        var result = generateRequest();

        assertThat(result, hasStatus(204));
        verify(dynamoService).updatePhoneNumber(EMAIL_ADDRESS, NEW_PHONE_NUMBER);
        verify(sqsClient)
                .send(
                        objectMapper.writeValueAsString(
                                new NotifyRequest(
                                        EMAIL_ADDRESS,
                                        PHONE_NUMBER_UPDATED,
                                        SupportedLanguage.EN)));
        verify(auditService)
                .submitAuditEvent(
                        AccountManagementAuditableEvent.UPDATE_PHONE_NUMBER,
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        userProfile.getSubjectID(),
                        userProfile.getEmail(),
                        "123.123.123.123",
                        NEW_PHONE_NUMBER,
                        PERSISTENT_ID);
    }

    @Test
    void shouldReturn400WhenRequestIsMissingParameters() {
        APIGatewayProxyRequestEvent.ProxyRequestContext proxyRequestContext =
                new APIGatewayProxyRequestEvent.ProxyRequestContext();
        Map<String, Object> authorizerParams = new HashMap<>();
        authorizerParams.put("principalId", PUBLIC_SUBJECT.getValue());
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
    void shouldReturn400WhenOtpCodeIsNotValid() {
        when(codeStorageService.isValidOtpCode(EMAIL_ADDRESS, OTP, VERIFY_PHONE_NUMBER))
                .thenReturn(false);

        var result = generateRequest();

        verify(dynamoService, times(0)).updatePhoneNumber(EMAIL_ADDRESS, NEW_PHONE_NUMBER);
        verifyNoInteractions(sqsClient);
        verifyNoInteractions(auditService);
        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1020));
    }

    @Test
    void shouldReturn400IfUserAccountDoesNotExistForCurrentEmail() {
        when(codeStorageService.isValidOtpCode(EMAIL_ADDRESS, OTP, VERIFY_PHONE_NUMBER))
                .thenReturn(true);
        when(dynamoService.getUserProfileByEmailMaybe(EMAIL_ADDRESS)).thenReturn(Optional.empty());

        var result = generateRequest();

        verify(dynamoService, times(0)).updatePhoneNumber(EMAIL_ADDRESS, NEW_PHONE_NUMBER);
        verifyNoInteractions(sqsClient);
        verifyNoInteractions(auditService);
        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1010));
    }

    private APIGatewayProxyResponseEvent generateRequest() {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody(
                format(
                        "{\"email\": \"%s\", \"phoneNumber\": \"%s\", \"otp\": \"%s\"  }",
                        EMAIL_ADDRESS, NEW_PHONE_NUMBER, OTP));
        APIGatewayProxyRequestEvent.ProxyRequestContext proxyRequestContext =
                new APIGatewayProxyRequestEvent.ProxyRequestContext();
        Map<String, Object> authorizerParams = new HashMap<>();
        authorizerParams.put("principalId", PUBLIC_SUBJECT.getValue());
        proxyRequestContext.setAuthorizer(authorizerParams);
        proxyRequestContext.setIdentity(identityWithSourceIp("123.123.123.123"));
        event.setRequestContext(proxyRequestContext);
        event.setHeaders(Map.of(PersistentIdHelper.PERSISTENT_ID_HEADER_NAME, PERSISTENT_ID));

        return handler.handleRequest(event, context);
    }
}
