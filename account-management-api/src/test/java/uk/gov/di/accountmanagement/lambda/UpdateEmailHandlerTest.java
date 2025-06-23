package uk.gov.di.accountmanagement.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import uk.gov.di.accountmanagement.domain.AccountManagementAuditableEvent;
import uk.gov.di.accountmanagement.entity.NotifyRequest;
import uk.gov.di.accountmanagement.entity.UpdateEmailRequest;
import uk.gov.di.accountmanagement.exceptions.InvalidPrincipalException;
import uk.gov.di.accountmanagement.helpers.AuditHelper;
import uk.gov.di.accountmanagement.services.AwsSqsClient;
import uk.gov.di.accountmanagement.services.CodeStorageService;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.shared.entity.EmailCheckResultStatus;
import uk.gov.di.authentication.shared.entity.EmailCheckResultStore;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.helpers.ClientSessionIdHelper;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.helpers.LocaleHelper.SupportedLanguage;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.helpers.SaltHelper;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoEmailCheckResultService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.SerializationService;
import uk.gov.di.authentication.sharedtest.logging.CaptureLoggingExtension;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.di.accountmanagement.entity.NotificationType.EMAIL_UPDATED;
import static uk.gov.di.accountmanagement.entity.NotificationType.VERIFY_EMAIL;
import static uk.gov.di.authentication.sharedtest.helper.RequestEventHelper.identityWithSourceIp;
import static uk.gov.di.authentication.sharedtest.logging.LogEventMatcher.withMessageContaining;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class UpdateEmailHandlerTest {

    private final Context context = mock(Context.class);
    private final DynamoService dynamoService = mock(DynamoService.class);
    private final DynamoEmailCheckResultService dynamoEmailCheckResultService =
            mock(DynamoEmailCheckResultService.class);
    private final AwsSqsClient sqsClient = mock(AwsSqsClient.class);
    private final CodeStorageService codeStorageService = mock(CodeStorageService.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private UpdateEmailHandler handler;
    private static final String EXISTING_EMAIL_ADDRESS = "joe.bloggs@digital.cabinet-office.gov.uk";
    private static final String NEW_EMAIL_ADDRESS = "bloggs.joe@digital.cabinet-office.gov.uk";
    private static final String INVALID_EMAIL_ADDRESS = "digital.cabinet-office.gov.uk";
    private static final String PERSISTENT_ID = "some-persistent-session-id";
    private static final String CLIENT_ID = "some-client-id";
    private static final String SESSION_ID = "some-session-id";
    private static final byte[] SALT = SaltHelper.generateNewSalt();
    private static final String OTP = "123456";
    private static final String TXMA_ENCODED_HEADER_VALUE = "txma-test-value";
    private static final Subject INTERNAL_SUBJECT = new Subject();
    private final String expectedCommonSubject =
            ClientSubjectHelper.calculatePairwiseIdentifier(
                    INTERNAL_SUBJECT.getValue(), "test.account.gov.uk", SALT);
    private final AuditContext auditContext =
            new AuditContext(
                    CLIENT_ID,
                    SESSION_ID,
                    AuditService.UNKNOWN,
                    expectedCommonSubject,
                    NEW_EMAIL_ADDRESS,
                    "123.123.123.123",
                    null,
                    PERSISTENT_ID,
                    Optional.of(TXMA_ENCODED_HEADER_VALUE),
                    new ArrayList<>());

    private final Json objectMapper = SerializationService.getInstance();
    private final AuditService auditService = mock(AuditService.class);

    @RegisterExtension
    private final CaptureLoggingExtension logging =
            new CaptureLoggingExtension(UpdateEmailHandler.class);

    @BeforeEach
    void setUp() {
        handler =
                new UpdateEmailHandler(
                        dynamoService,
                        dynamoEmailCheckResultService,
                        sqsClient,
                        codeStorageService,
                        auditService,
                        configurationService);
        when(configurationService.getInternalSectorUri()).thenReturn("https://test.account.gov.uk");
        when(configurationService.isEmailCheckEnabled()).thenReturn(true);
        when(dynamoService.getOrGenerateSalt(any(UserProfile.class))).thenReturn(SALT);
    }

    @Test
    void shouldReturn204WhenPrincipalContainsInternalPairwiseSubjectId() throws Json.JsonException {
        var userProfile = new UserProfile().withSubjectID(INTERNAL_SUBJECT.getValue());
        when(dynamoService.getUserProfileByEmailMaybe(EXISTING_EMAIL_ADDRESS))
                .thenReturn(Optional.of(userProfile));
        when(codeStorageService.isValidOtpCode(NEW_EMAIL_ADDRESS, OTP, VERIFY_EMAIL))
                .thenReturn(true);
        when(dynamoEmailCheckResultService.getEmailCheckStore(NEW_EMAIL_ADDRESS))
                .thenReturn(
                        Optional.of(
                                new EmailCheckResultStore()
                                        .withEmail(NEW_EMAIL_ADDRESS)
                                        .withStatus(EmailCheckResultStatus.ALLOW)));

        var event = generateApiGatewayEvent(NEW_EMAIL_ADDRESS, expectedCommonSubject);
        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(204));
        verify(dynamoService).updateEmail(EXISTING_EMAIL_ADDRESS, NEW_EMAIL_ADDRESS);
        verify(sqsClient)
                .send(
                        objectMapper.writeValueAsString(
                                new NotifyRequest(
                                        NEW_EMAIL_ADDRESS, EMAIL_UPDATED, SupportedLanguage.EN)));

        verify(auditService)
                .submitAuditEvent(
                        AccountManagementAuditableEvent.AUTH_UPDATE_EMAIL,
                        auditContext,
                        AuditService.MetadataPair.pair(
                                "replacedEmail", EXISTING_EMAIL_ADDRESS, true));
        assertThat(
                logging.events(),
                hasItem(
                        withMessageContaining(
                                "UpdateEmailHandler: Experian email verification status: ALLOW")));
    }

    @Test
    void shouldSubmitAuditEventWhenEmailCheckResultRecordDoesNotExist() {
        var userProfile = new UserProfile().withSubjectID(INTERNAL_SUBJECT.getValue());
        when(dynamoService.getUserProfileByEmailMaybe(EXISTING_EMAIL_ADDRESS))
                .thenReturn(Optional.of(userProfile));
        when(codeStorageService.isValidOtpCode(NEW_EMAIL_ADDRESS, OTP, VERIFY_EMAIL))
                .thenReturn(true);
        when(dynamoEmailCheckResultService.getEmailCheckStore(NEW_EMAIL_ADDRESS))
                .thenReturn(Optional.empty());

        long mockedTimestamp = 1719376320;
        try (MockedStatic<NowHelper> mockedNowHelperClass = Mockito.mockStatic(NowHelper.class)) {
            mockedNowHelperClass
                    .when(() -> NowHelper.toUnixTimestamp(NowHelper.now()))
                    .thenReturn(mockedTimestamp);
            var event = generateApiGatewayEvent(NEW_EMAIL_ADDRESS, expectedCommonSubject);
            handler.handleRequest(event, context);

            assertThat(
                    logging.events(),
                    hasItem(
                            withMessageContaining(
                                    "UpdateEmailHandler: Experian email verification status: PENDING")));

            verify(auditService)
                    .submitAuditEvent(
                            AccountManagementAuditableEvent.AUTH_EMAIL_FRAUD_CHECK_BYPASSED,
                            auditContext.withSubjectId(INTERNAL_SUBJECT.getValue()),
                            AuditService.MetadataPair.pair(
                                    "journey_type", JourneyType.ACCOUNT_MANAGEMENT.getValue()),
                            AuditService.MetadataPair.pair(
                                    "assessment_checked_at_timestamp", mockedTimestamp),
                            AuditService.MetadataPair.pair("iss", "AUTH"));
        }
    }

    @Test
    void shouldThrowIfPrincipalIdIsInvalid() {
        var userProfile =
                new UserProfile()
                        .withPublicSubjectID(new Subject().getValue())
                        .withSubjectID(new Subject().getValue());
        when(dynamoService.getUserProfileByEmailMaybe(EXISTING_EMAIL_ADDRESS))
                .thenReturn(Optional.of(userProfile));
        when(codeStorageService.isValidOtpCode(NEW_EMAIL_ADDRESS, OTP, VERIFY_EMAIL))
                .thenReturn(true);
        when(dynamoService.getOrGenerateSalt(userProfile)).thenReturn(SaltHelper.generateNewSalt());
        var event = generateApiGatewayEvent(NEW_EMAIL_ADDRESS, expectedCommonSubject);

        var expectedException =
                assertThrows(
                        InvalidPrincipalException.class,
                        () -> handler.handleRequest(event, context),
                        "Expected to throw exception");

        assertThat(expectedException.getMessage(), equalTo("Invalid Principal in request"));
        verifyNoInteractions(sqsClient);
    }

    @Test
    void shouldReturn400WhenReplacementEmailAlreadyExists() {
        when(codeStorageService.isValidOtpCode(NEW_EMAIL_ADDRESS, OTP, VERIFY_EMAIL))
                .thenReturn(true);
        when(dynamoService.userExists(NEW_EMAIL_ADDRESS)).thenReturn(true);

        var event = generateApiGatewayEvent(NEW_EMAIL_ADDRESS, expectedCommonSubject);
        var result = handler.handleRequest(event, context);

        verify(dynamoService, never()).updateEmail(EXISTING_EMAIL_ADDRESS, NEW_EMAIL_ADDRESS);
        verifyNoInteractions(sqsClient);
        verifyNoInteractions(auditService);
        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1009));
    }

    @Test
    void shouldReturn400WhenRequestIsMissingParameters() {
        APIGatewayProxyRequestEvent.ProxyRequestContext proxyRequestContext =
                new APIGatewayProxyRequestEvent.ProxyRequestContext();
        Map<String, Object> authorizerParams = new HashMap<>();
        authorizerParams.put("principalId", expectedCommonSubject);
        proxyRequestContext.setAuthorizer(authorizerParams);
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setRequestContext(proxyRequestContext);
        event.setBody(format("{\"existingEmailAddress\": \"%s\"}", EXISTING_EMAIL_ADDRESS));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1001));
        verifyNoInteractions(sqsClient);
        verifyNoInteractions(auditService);
        verifyNoInteractions(dynamoService);
    }

    @Test
    void shouldReturnErrorWhenOtpCodeIsNotValid() {
        when(codeStorageService.isValidOtpCode(INVALID_EMAIL_ADDRESS, OTP, VERIFY_EMAIL))
                .thenReturn(false);

        var event = generateApiGatewayEvent(NEW_EMAIL_ADDRESS, expectedCommonSubject);
        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1020));
        verify(dynamoService, never()).updateEmail(EXISTING_EMAIL_ADDRESS, INVALID_EMAIL_ADDRESS);
        verifyNoInteractions(sqsClient);
        verifyNoInteractions(auditService);
    }

    @Test
    void shouldReturn400AndNotUpdateEmailWhenEmailIsInvalid() {
        when(codeStorageService.isValidOtpCode(INVALID_EMAIL_ADDRESS, OTP, VERIFY_EMAIL))
                .thenReturn(true);

        var event = generateApiGatewayEvent(INVALID_EMAIL_ADDRESS, expectedCommonSubject);
        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1004));
        verify(dynamoService, never()).updateEmail(EXISTING_EMAIL_ADDRESS, INVALID_EMAIL_ADDRESS);
        verifyNoInteractions(sqsClient);
        verifyNoInteractions(auditService);
    }

    @Test
    void shouldReturn400IfUserAccountDoesNotExistForCurrentEmail() {
        when(dynamoService.getUserProfileByEmailMaybe(EXISTING_EMAIL_ADDRESS))
                .thenReturn(Optional.empty());
        when(codeStorageService.isValidOtpCode(NEW_EMAIL_ADDRESS, OTP, VERIFY_EMAIL))
                .thenReturn(true);

        var event = generateApiGatewayEvent(NEW_EMAIL_ADDRESS, expectedCommonSubject);
        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1010));
        verify(dynamoService, never()).updateEmail(EXISTING_EMAIL_ADDRESS, INVALID_EMAIL_ADDRESS);
        verifyNoInteractions(sqsClient);
        verifyNoInteractions(auditService);
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

    private APIGatewayProxyRequestEvent generateApiGatewayEvent(
            String replacementEmail, String principalId) {
        var event = new APIGatewayProxyRequestEvent();
        event.setBody(
                format(
                        "{\"existingEmailAddress\": \"%s\", \"replacementEmailAddress\": \"%s\", \"otp\": \"%s\"  }",
                        EXISTING_EMAIL_ADDRESS, replacementEmail, OTP));
        APIGatewayProxyRequestEvent.ProxyRequestContext proxyRequestContext =
                new APIGatewayProxyRequestEvent.ProxyRequestContext();
        Map<String, Object> authorizerParams = new HashMap<>();
        authorizerParams.put("principalId", principalId);
        authorizerParams.put("clientId", CLIENT_ID);
        proxyRequestContext.setAuthorizer(authorizerParams);
        proxyRequestContext.setIdentity(identityWithSourceIp("123.123.123.123"));
        event.setRequestContext(proxyRequestContext);
        event.setHeaders(
                Map.of(
                        PersistentIdHelper.PERSISTENT_ID_HEADER_NAME,
                        PERSISTENT_ID,
                        ClientSessionIdHelper.SESSION_ID_HEADER_NAME,
                        SESSION_ID,
                        AuditHelper.TXMA_ENCODED_HEADER_NAME,
                        TXMA_ENCODED_HEADER_VALUE));

        return event;
    }
}
