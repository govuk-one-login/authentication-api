package uk.gov.di.accountmanagement.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import software.amazon.awssdk.core.exception.SdkClientException;
import uk.gov.di.accountmanagement.domain.AccountManagementAuditableEvent;
import uk.gov.di.accountmanagement.entity.NotificationType;
import uk.gov.di.accountmanagement.entity.NotifyRequest;
import uk.gov.di.accountmanagement.services.AwsSqsClient;
import uk.gov.di.accountmanagement.services.CodeStorageService;
import uk.gov.di.authentication.shared.domain.RequestHeaders;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.helpers.AuditHelper;
import uk.gov.di.authentication.shared.helpers.ClientSessionIdHelper;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.helpers.LocaleHelper.SupportedLanguage;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.helpers.SaltHelper;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.CodeGeneratorService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.SerializationService;

import java.util.Date;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

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
    private static final String TEST_TEST_USER_EMAIL_ADDRESS =
            "tester.joe.bloggs@digital.cabinet-office.gov.uk";
    private static final String TEST_CLIENT_ID = "tester-client-id";
    private static final String SESSION_ID = "some-client-session-id";
    private static final String TEST_SIX_DIGIT_CODE = "123456";
    private static final String TEST_CLIENT_AND_USER_SIX_DIGIT_CODE = "654321";
    private static final String TEST_PHONE_NUMBER = "07755551084";
    private static final String TXMA_ENCODED_HEADER_VALUE = "txma-test-value";
    private static final long CODE_EXPIRY_TIME = 900;
    private static final byte[] SALT = SaltHelper.generateNewSalt();
    private static final Subject INTERNAL_SUBJECT = new Subject();
    private final String expectedCommonSubject =
            ClientSubjectHelper.calculatePairwiseIdentifier(
                    INTERNAL_SUBJECT.getValue(), "test.account.gov.uk", SALT);
    private final Json objectMapper = SerializationService.getInstance();
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final AwsSqsClient emailSqsClient = mock(AwsSqsClient.class);
    private final AwsSqsClient pendingEmailCheckSqsClient = mock(AwsSqsClient.class);
    private final CodeGeneratorService codeGeneratorService = mock(CodeGeneratorService.class);
    private final CodeStorageService codeStorageService = mock(CodeStorageService.class);
    private final DynamoService dynamoService = mock(DynamoService.class);
    private final Context context = mock(Context.class);
    private final ClientService clientService = mock(ClientService.class);
    private final AuditService auditService = mock(AuditService.class);
    private APIGatewayProxyRequestEvent.ProxyRequestContext eventContext;

    private final SendOtpNotificationHandler handler =
            new SendOtpNotificationHandler(
                    configurationService,
                    emailSqsClient,
                    pendingEmailCheckSqsClient,
                    codeGeneratorService,
                    codeStorageService,
                    dynamoService,
                    auditService,
                    clientService);

    @BeforeEach
    void setup() {
        when(configurationService.getDefaultOtpCodeExpiry()).thenReturn(CODE_EXPIRY_TIME);
        when(configurationService.isEmailCheckEnabled()).thenReturn(true);
        when(codeGeneratorService.sixDigitCode()).thenReturn(TEST_SIX_DIGIT_CODE);
        when(configurationService.getTestClientVerifyEmailOTP())
                .thenReturn(Optional.of(TEST_CLIENT_AND_USER_SIX_DIGIT_CODE));
        when(configurationService.getTestClientVerifyPhoneNumberOTP())
                .thenReturn(Optional.of(TEST_CLIENT_AND_USER_SIX_DIGIT_CODE));
        when(clientService.isTestJourney(TEST_CLIENT_ID, TEST_TEST_USER_EMAIL_ADDRESS))
                .thenReturn(true);

        eventContext = contextWithSourceIp("123.123.123.123");
        Map<String, Object> authorizer =
                Map.of("clientId", TEST_CLIENT_ID, "principalId", expectedCommonSubject);
        eventContext.setAuthorizer(authorizer);
    }

    @Test
    void shouldReturn204AndPutMessageOnQueueForAValidEmailRequest() throws Json.JsonException {
        String persistentIdValue = "some-persistent-session-id";
        NotifyRequest notifyRequest =
                new NotifyRequest(
                        TEST_EMAIL_ADDRESS,
                        VERIFY_EMAIL,
                        TEST_SIX_DIGIT_CODE,
                        SupportedLanguage.EN);
        String serialisedRequest = objectMapper.writeValueAsString(notifyRequest);

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(
                Map.of(
                        PersistentIdHelper.PERSISTENT_ID_HEADER_NAME,
                        persistentIdValue,
                        RequestHeaders.SESSION_ID_HEADER,
                        "some-session-id",
                        RequestHeaders.CLIENT_SESSION_ID_HEADER,
                        "some-client-session-id",
                        AuditHelper.TXMA_ENCODED_HEADER_NAME,
                        TXMA_ENCODED_HEADER_VALUE));
        event.setRequestContext(eventContext);
        event.setBody(
                format(
                        "{ \"email\": \"%s\", \"notificationType\": \"%s\" }",
                        TEST_EMAIL_ADDRESS, VERIFY_EMAIL));

        Date mockedDate = new Date();
        UUID mockedUUID = UUID.fromString("5fc03087-d265-11e7-b8c6-83e29cd24f4c");
        try (MockedStatic<NowHelper> mockedNowHelperClass = Mockito.mockStatic(NowHelper.class)) {
            try (MockedStatic<UUID> mockedUUIDClass = Mockito.mockStatic(UUID.class)) {
                mockedNowHelperClass.when(NowHelper::now).thenReturn(mockedDate);
                mockedUUIDClass.when(UUID::randomUUID).thenReturn(mockedUUID);

                APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);
                assertEquals(204, result.getStatusCode());

                verify(emailSqsClient).send(serialisedRequest);
                verify(pendingEmailCheckSqsClient)
                        .send(
                                format(
                                        "{\"userId\":\"%s\",\"requestReference\":\"%s\",\"emailAddress\":\"%s\",\"userSessionId\":\"%s\",\"govukSigninJourneyId\":\"%s\",\"persistentSessionId\":\"%s\",\"ipAddress\":\"%s\",\"journeyType\":\"%s\",\"timeOfInitialRequest\":%d,\"isTestUserRequest\":%b}",
                                        expectedCommonSubject,
                                        mockedUUID,
                                        TEST_EMAIL_ADDRESS,
                                        "some-session-id",
                                        "some-client-session-id",
                                        "some-persistent-session-id",
                                        "123.123.123.123",
                                        JourneyType.ACCOUNT_MANAGEMENT,
                                        mockedDate.toInstant().getEpochSecond(),
                                        false));
                verify(codeStorageService)
                        .saveOtpCode(
                                TEST_EMAIL_ADDRESS,
                                TEST_SIX_DIGIT_CODE,
                                CODE_EXPIRY_TIME,
                                VERIFY_EMAIL);

                verify(auditService)
                        .submitAuditEvent(
                                AccountManagementAuditableEvent.SEND_OTP,
                                TEST_CLIENT_ID,
                                SESSION_ID,
                                AuditService.UNKNOWN,
                                expectedCommonSubject,
                                TEST_EMAIL_ADDRESS,
                                "123.123.123.123",
                                null,
                                persistentIdValue,
                                new AuditService.RestrictedSection(
                                        Optional.of(TXMA_ENCODED_HEADER_VALUE)),
                                pair("notification-type", VERIFY_EMAIL),
                                pair("test-user", false));
            }
        }
    }

    @Test
    void shouldReturn204AndNotEnqueuePendingEmailCheckWhenFeatureFlagDisabled()
            throws Json.JsonException {
        when(configurationService.isEmailCheckEnabled()).thenReturn(false);

        String persistentIdValue = "some-persistent-session-id";
        NotifyRequest notifyRequest =
                new NotifyRequest(
                        TEST_EMAIL_ADDRESS,
                        VERIFY_EMAIL,
                        TEST_SIX_DIGIT_CODE,
                        SupportedLanguage.EN);
        String serialisedRequest = objectMapper.writeValueAsString(notifyRequest);

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(
                Map.of(
                        PersistentIdHelper.PERSISTENT_ID_HEADER_NAME,
                        persistentIdValue,
                        RequestHeaders.SESSION_ID_HEADER,
                        "some-session-id",
                        RequestHeaders.CLIENT_SESSION_ID_HEADER,
                        "some-client-session-id",
                        AuditHelper.TXMA_ENCODED_HEADER_NAME,
                        TXMA_ENCODED_HEADER_VALUE));
        event.setRequestContext(eventContext);
        event.setBody(
                format(
                        "{ \"email\": \"%s\", \"notificationType\": \"%s\" }",
                        TEST_EMAIL_ADDRESS, VERIFY_EMAIL));

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);
        assertEquals(204, result.getStatusCode());

        verifyNoInteractions(pendingEmailCheckSqsClient);
    }

    @Test
    void shouldReturn204AndPutMessageOnQueueForAValidPhoneRequest() throws Json.JsonException {
        NotifyRequest notifyRequest =
                new NotifyRequest(
                        TEST_PHONE_NUMBER,
                        VERIFY_PHONE_NUMBER,
                        TEST_SIX_DIGIT_CODE,
                        SupportedLanguage.EN);

        String serialisedRequest = objectMapper.writeValueAsString(notifyRequest);

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(
                Map.of(
                        ClientSessionIdHelper.SESSION_ID_HEADER_NAME,
                        SESSION_ID,
                        AuditHelper.TXMA_ENCODED_HEADER_NAME,
                        TXMA_ENCODED_HEADER_VALUE));
        event.setRequestContext(eventContext);
        event.setBody(
                format(
                        "{ \"email\": \"%s\", \"notificationType\": \"%s\", \"phoneNumber\": \"%s\"  }",
                        TEST_EMAIL_ADDRESS, VERIFY_PHONE_NUMBER, TEST_PHONE_NUMBER));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertEquals(204, result.getStatusCode());

        verify(emailSqsClient).send(serialisedRequest);
        verify(codeStorageService)
                .saveOtpCode(
                        TEST_EMAIL_ADDRESS,
                        TEST_SIX_DIGIT_CODE,
                        CODE_EXPIRY_TIME,
                        VERIFY_PHONE_NUMBER);

        verify(auditService)
                .submitAuditEvent(
                        AccountManagementAuditableEvent.SEND_OTP,
                        TEST_CLIENT_ID,
                        SESSION_ID,
                        AuditService.UNKNOWN,
                        expectedCommonSubject,
                        TEST_EMAIL_ADDRESS,
                        "123.123.123.123",
                        TEST_PHONE_NUMBER,
                        PersistentIdHelper.PERSISTENT_ID_UNKNOWN_VALUE,
                        new AuditService.RestrictedSection(Optional.of(TXMA_ENCODED_HEADER_VALUE)),
                        pair("notification-type", VERIFY_PHONE_NUMBER),
                        pair("test-user", false));
    }

    @Test
    void shouldReturn204AndNotPutMessageOnQueueForAValidEmailRequestFromTestUser() {
        when(configurationService.isTestClientsEnabled()).thenReturn(true);

        String persistentIdValue = "some-persistent-session-id";

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(
                Map.of(
                        PersistentIdHelper.PERSISTENT_ID_HEADER_NAME,
                        persistentIdValue,
                        ClientSessionIdHelper.SESSION_ID_HEADER_NAME,
                        SESSION_ID,
                        AuditHelper.TXMA_ENCODED_HEADER_NAME,
                        TXMA_ENCODED_HEADER_VALUE));
        event.setRequestContext(eventContext);
        event.setBody(
                format(
                        "{ \"email\": \"%s\", \"notificationType\": \"%s\" }",
                        TEST_TEST_USER_EMAIL_ADDRESS, VERIFY_EMAIL));

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertEquals(204, result.getStatusCode());

        verifyNoInteractions(emailSqsClient);
        verify(codeStorageService)
                .saveOtpCode(
                        TEST_TEST_USER_EMAIL_ADDRESS,
                        TEST_CLIENT_AND_USER_SIX_DIGIT_CODE,
                        CODE_EXPIRY_TIME,
                        VERIFY_EMAIL);

        verify(auditService)
                .submitAuditEvent(
                        AccountManagementAuditableEvent.SEND_OTP,
                        TEST_CLIENT_ID,
                        SESSION_ID,
                        AuditService.UNKNOWN,
                        expectedCommonSubject,
                        TEST_TEST_USER_EMAIL_ADDRESS,
                        "123.123.123.123",
                        null,
                        persistentIdValue,
                        new AuditService.RestrictedSection(Optional.of(TXMA_ENCODED_HEADER_VALUE)),
                        pair("notification-type", VERIFY_EMAIL),
                        pair("test-user", true));
    }

    @Test
    void shouldReturn500OnRequestFromTestUserIfTestClientsNotEnabled() {
        when(configurationService.isTestClientsEnabled()).thenReturn(false);
        String persistentIdValue = "some-persistent-session-id";

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(
                Map.of(
                        PersistentIdHelper.PERSISTENT_ID_HEADER_NAME,
                        persistentIdValue,
                        AuditHelper.TXMA_ENCODED_HEADER_NAME,
                        TXMA_ENCODED_HEADER_VALUE));
        event.setRequestContext(eventContext);
        event.setBody(
                format(
                        "{ \"email\": \"%s\", \"notificationType\": \"%s\" }",
                        TEST_TEST_USER_EMAIL_ADDRESS, VERIFY_EMAIL));

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertEquals(500, result.getStatusCode());

        verifyNoInteractions(emailSqsClient, codeStorageService, auditService);
    }

    @Test
    void shouldReturn400IfRequestIsMissingEmail() {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of());
        event.setBody("{ }");
        event.setRequestContext(eventContext);
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertEquals(400, result.getStatusCode());
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1001));

        verifyNoInteractions(auditService);
    }

    @Test
    void shouldReturn400IfEmailAddressIsInvalid() {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of());
        event.setRequestContext(eventContext);
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
    void shouldReturn400IfPhoneNumberIsInvalid() {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of());
        event.setRequestContext(eventContext);
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
    void shouldReturn400IfNewPhoneNumberIsTheSameAsCurrentPhoneNumber() {
        when(dynamoService.getUserProfileByEmailMaybe(TEST_EMAIL_ADDRESS))
                .thenReturn(
                        Optional.of(
                                new UserProfile()
                                        .withEmail(TEST_EMAIL_ADDRESS)
                                        .withPhoneNumber("+447755551084")
                                        .withPhoneNumberVerified(true)));
        var event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of());
        event.setRequestContext(eventContext);
        event.setBody(
                format(
                        "{ \"email\": \"%s\", \"notificationType\": \"%s\", \"phoneNumber\": \"%s\" }",
                        TEST_EMAIL_ADDRESS, VERIFY_PHONE_NUMBER, TEST_PHONE_NUMBER));

        var result = handler.handleRequest(event, context);

        assertEquals(400, result.getStatusCode());
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1044));
        verifyNoInteractions(auditService);
    }

    @Test
    void shouldReturn500IfMessageCannotBeSentToQueue() throws Json.JsonException {
        NotifyRequest notifyRequest =
                new NotifyRequest(
                        TEST_EMAIL_ADDRESS,
                        VERIFY_EMAIL,
                        TEST_SIX_DIGIT_CODE,
                        SupportedLanguage.EN);
        String serialisedRequest = objectMapper.writeValueAsString(notifyRequest);
        Mockito.doThrow(SdkClientException.class).when(emailSqsClient).send(eq(serialisedRequest));

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of());
        event.setRequestContext(eventContext);
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
    void shouldReturn400WhenInvalidNotificationType() {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of());
        event.setRequestContext(eventContext);
        event.setBody(
                format(
                        "{ \"email\": \"%s\", \"notificationType\": \"%s\" }",
                        TEST_EMAIL_ADDRESS, "VERIFY_PASSWORD"));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertEquals(400, result.getStatusCode());
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1001));

        verify(emailSqsClient, never()).send(anyString());
        verify(codeStorageService, never())
                .saveOtpCode(anyString(), anyString(), anyLong(), any(NotificationType.class));

        verifyNoInteractions(auditService);
    }

    @Test
    void shouldReturn400WhenAccountAlreadyExistsWithGivenEmail() {
        when(dynamoService.userExists(eq(TEST_EMAIL_ADDRESS))).thenReturn(true);

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of());
        event.setRequestContext(eventContext);
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
