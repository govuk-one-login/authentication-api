package uk.gov.di.accountmanagement.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.accountmanagement.domain.AccountManagementAuditableEvent;
import uk.gov.di.accountmanagement.entity.NotifyRequest;
import uk.gov.di.accountmanagement.entity.UpdateEmailRequest;
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
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.di.accountmanagement.entity.NotificationType.EMAIL_UPDATED;
import static uk.gov.di.accountmanagement.entity.NotificationType.VERIFY_EMAIL;
import static uk.gov.di.authentication.sharedtest.helper.RequestEventHelper.identityWithSourceIp;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class UpdateEmailHandlerTest {

    private final Context context = mock(Context.class);
    private final DynamoService dynamoService = mock(DynamoService.class);
    private final AwsSqsClient sqsClient = mock(AwsSqsClient.class);
    private final CodeStorageService codeStorageService = mock(CodeStorageService.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private UpdateEmailHandler handler;
    private static final String EXISTING_EMAIL_ADDRESS = "joe.bloggs@digital.cabinet-office.gov.uk";
    private static final String NEW_EMAIL_ADDRESS = "bloggs.joe@digital.cabinet-office.gov.uk";
    private static final String INVALID_EMAIL_ADDRESS = "igital.cabinet-office.gov.uk";
    private static final String PERSISTENT_ID = "some-persistent-session-id";
    private static final String OTP = "123456";
    private static final Subject PUBLIC_SUBJECT = new Subject();

    private final Json objectMapper = SerializationService.getInstance();
    private final AuditService auditService = mock(AuditService.class);

    @BeforeEach
    void setUp() {
        handler =
                new UpdateEmailHandler(
                        dynamoService,
                        sqsClient,
                        codeStorageService,
                        auditService,
                        configurationService);
    }

    @Test
    void shouldReturn204ForValidUpdateEmailRequest() throws Json.JsonException {
        var userProfile = new UserProfile().withPublicSubjectID(PUBLIC_SUBJECT.getValue());
        when(dynamoService.getUserProfileByEmailMaybe(EXISTING_EMAIL_ADDRESS))
                .thenReturn(Optional.of(userProfile));
        when(codeStorageService.isValidOtpCode(NEW_EMAIL_ADDRESS, OTP, VERIFY_EMAIL))
                .thenReturn(true);

        var result = generateRequest(NEW_EMAIL_ADDRESS);

        assertThat(result, hasStatus(204));
        verify(dynamoService).updateEmail(EXISTING_EMAIL_ADDRESS, NEW_EMAIL_ADDRESS);
        NotifyRequest notifyRequest =
                new NotifyRequest(NEW_EMAIL_ADDRESS, EMAIL_UPDATED, SupportedLanguage.EN);
        verify(sqsClient).send(objectMapper.writeValueAsString(notifyRequest));

        verify(auditService)
                .submitAuditEvent(
                        AccountManagementAuditableEvent.UPDATE_EMAIL,
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        userProfile.getSubjectID(),
                        NEW_EMAIL_ADDRESS,
                        "123.123.123.123",
                        userProfile.getPhoneNumber(),
                        PERSISTENT_ID);
    }

    @Test
    void shouldReturn400WhenReplacementEmailAlreadyExists() throws Json.JsonException {
        when(codeStorageService.isValidOtpCode(NEW_EMAIL_ADDRESS, OTP, VERIFY_EMAIL))
                .thenReturn(true);
        when(dynamoService.userExists(NEW_EMAIL_ADDRESS)).thenReturn(true);

        var result = generateRequest(NEW_EMAIL_ADDRESS);

        verify(dynamoService, never()).updateEmail(EXISTING_EMAIL_ADDRESS, NEW_EMAIL_ADDRESS);
        verify(sqsClient, never())
                .send(
                        objectMapper.writeValueAsString(
                                new NotifyRequest(
                                        NEW_EMAIL_ADDRESS, EMAIL_UPDATED, SupportedLanguage.EN)));
        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1009));
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
        event.setBody(format("{\"existingEmailAddress\": \"%s\"}", EXISTING_EMAIL_ADDRESS));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1001));
    }

    @Test
    public void shouldReturnErrorWhenOtpCodeIsNotValid() throws Json.JsonException {
        when(codeStorageService.isValidOtpCode(INVALID_EMAIL_ADDRESS, OTP, VERIFY_EMAIL))
                .thenReturn(false);

        var result = generateRequest(NEW_EMAIL_ADDRESS);

        assertThat(result, hasStatus(400));
        verify(dynamoService, never()).updateEmail(EXISTING_EMAIL_ADDRESS, INVALID_EMAIL_ADDRESS);
        NotifyRequest notifyRequest =
                new NotifyRequest(INVALID_EMAIL_ADDRESS, EMAIL_UPDATED, SupportedLanguage.EN);
        verify(sqsClient, never()).send(objectMapper.writeValueAsString(notifyRequest));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1020));
    }

    @Test
    void shouldReturn400AndNotUpdateEmailWhenEmailIsInvalid() throws Json.JsonException {
        when(codeStorageService.isValidOtpCode(INVALID_EMAIL_ADDRESS, OTP, VERIFY_EMAIL))
                .thenReturn(true);

        APIGatewayProxyResponseEvent result = generateRequest(INVALID_EMAIL_ADDRESS);

        assertThat(result, hasStatus(400));
        verify(dynamoService, never()).updateEmail(EXISTING_EMAIL_ADDRESS, INVALID_EMAIL_ADDRESS);
        NotifyRequest notifyRequest =
                new NotifyRequest(INVALID_EMAIL_ADDRESS, EMAIL_UPDATED, SupportedLanguage.EN);
        verify(sqsClient, never()).send(objectMapper.writeValueAsString(notifyRequest));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1004));
    }

    @Test
    void shouldReturn400IfUserAccountDoesNotExistForCurrentEmail() {
        when(dynamoService.getUserProfileByEmailMaybe(EXISTING_EMAIL_ADDRESS))
                .thenReturn(Optional.empty());
        when(codeStorageService.isValidOtpCode(INVALID_EMAIL_ADDRESS, OTP, VERIFY_EMAIL))
                .thenReturn(true);

        var result = generateRequest(INVALID_EMAIL_ADDRESS);

        assertThat(result, hasStatus(400));
        verify(dynamoService, never()).updateEmail(EXISTING_EMAIL_ADDRESS, INVALID_EMAIL_ADDRESS);
        verifyNoInteractions(sqsClient);
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1004));
    }

    @Test
    void shouldFormatAllEmailsToLowerCase() {
        final UpdateEmailRequest updateEmailRequest =
                new UpdateEmailRequest(
                        "Joe.Bloggs@digital.cabinet-office.gov.uk",
                        "Bloggs.Joe@digital.cabinet-office.gov.uk",
                        OTP);

        assertEquals(updateEmailRequest.getExistingEmailAddress(), EXISTING_EMAIL_ADDRESS);
        assertEquals(updateEmailRequest.getReplacementEmailAddress(), NEW_EMAIL_ADDRESS);
    }

    private APIGatewayProxyResponseEvent generateRequest(String replacementEmail) {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody(
                format(
                        "{\"existingEmailAddress\": \"%s\", \"replacementEmailAddress\": \"%s\", \"otp\": \"%s\"  }",
                        EXISTING_EMAIL_ADDRESS, replacementEmail, OTP));
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
