package uk.gov.di.accountmanagement.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.accountmanagement.domain.AccountManagementAuditableEvent;
import uk.gov.di.accountmanagement.entity.NotifyRequest;
import uk.gov.di.accountmanagement.exceptions.InvalidPrincipalException;
import uk.gov.di.accountmanagement.helpers.AuditHelper;
import uk.gov.di.accountmanagement.services.AwsSqsClient;
import uk.gov.di.accountmanagement.services.CodeStorageService;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.helpers.ClientSessionIdHelper;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.helpers.LocaleHelper.SupportedLanguage;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.helpers.SaltHelper;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.SerializationService;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
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
    private static final String PERSISTENT_ID = "some-persistent-session-id";
    private static final String CLIENT_SESSION_ID = "test-client-session-id";
    private static final String TXMA_ENCODED_HEADER_VALUE = "txma-test-value";
    private static final byte[] SALT = SaltHelper.generateNewSalt();
    private static final Subject INTERNAL_SUBJECT = new Subject();
    private final String expectedCommonSubject =
            ClientSubjectHelper.calculatePairwiseIdentifier(
                    INTERNAL_SUBJECT.getValue(), "test.account.gov.uk", SALT);

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
        when(configurationService.getInternalSectorUri()).thenReturn("https://test.account.gov.uk");
        when(dynamoService.getOrGenerateSalt(any(UserProfile.class))).thenReturn(SALT);
    }

    @Test
    void shouldReturn204WhenPrincipalContainsInternalPairwiseSubjectId() throws Json.JsonException {
        var userProfile =
                new UserProfile()
                        .withSubjectID(INTERNAL_SUBJECT.getValue())
                        .withPhoneNumber(OLD_PHONE_NUMBER);
        when(codeStorageService.isValidOtpCode(EMAIL_ADDRESS, OTP, VERIFY_PHONE_NUMBER))
                .thenReturn(true);
        when(dynamoService.getUserProfileByEmailMaybe(EMAIL_ADDRESS))
                .thenReturn(Optional.of(userProfile));

        var event = generateApiGatewayEvent(expectedCommonSubject);
        var result = handler.handleRequest(event, context);

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
                        AccountManagementAuditableEvent.AUTH_UPDATE_PHONE_NUMBER,
                        new AuditContext(
                                AuditService.UNKNOWN,
                                CLIENT_SESSION_ID,
                                AuditService.UNKNOWN,
                                expectedCommonSubject,
                                userProfile.getEmail(),
                                "123.123.123.123",
                                NEW_PHONE_NUMBER,
                                PERSISTENT_ID,
                                Optional.of(TXMA_ENCODED_HEADER_VALUE),
                                new ArrayList<>()));
    }

    @Test
    void shouldThrowIfPrincipalIdIsInvalid() {
        when(codeStorageService.isValidOtpCode(EMAIL_ADDRESS, OTP, VERIFY_PHONE_NUMBER))
                .thenReturn(true);
        var userProfile =
                new UserProfile()
                        .withPublicSubjectID(new Subject().getValue())
                        .withPhoneNumber(OLD_PHONE_NUMBER)
                        .withSubjectID(new Subject().getValue());
        when(dynamoService.getUserProfileByEmailMaybe(EMAIL_ADDRESS))
                .thenReturn(Optional.of(userProfile));
        when(dynamoService.getOrGenerateSalt(userProfile)).thenReturn(SaltHelper.generateNewSalt());
        var event = generateApiGatewayEvent(expectedCommonSubject);

        var expectedException =
                assertThrows(
                        InvalidPrincipalException.class,
                        () -> handler.handleRequest(event, context),
                        "Expected to throw exception");

        assertThat(expectedException.getMessage(), equalTo("Invalid Principal in request"));
        verifyNoInteractions(sqsClient);
        verifyNoInteractions(auditService);
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
        event.setBody(format("{\"email\": \"%s\"}", EMAIL_ADDRESS));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.REQUEST_MISSING_PARAMS));
        verifyNoInteractions(auditService);
        verifyNoInteractions(sqsClient);
    }

    @Test
    void shouldReturn400WhenOtpCodeIsNotValid() {
        when(codeStorageService.isValidOtpCode(EMAIL_ADDRESS, OTP, VERIFY_PHONE_NUMBER))
                .thenReturn(false);

        var event = generateApiGatewayEvent(expectedCommonSubject);
        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.INVALID_OTP));
        verify(dynamoService, times(0)).updatePhoneNumber(EMAIL_ADDRESS, NEW_PHONE_NUMBER);
        verifyNoInteractions(sqsClient);
        verifyNoInteractions(auditService);
    }

    @Test
    void shouldReturn400IfUserAccountDoesNotExistForCurrentEmail() {
        when(codeStorageService.isValidOtpCode(EMAIL_ADDRESS, OTP, VERIFY_PHONE_NUMBER))
                .thenReturn(true);
        when(dynamoService.getUserProfileByEmailMaybe(EMAIL_ADDRESS)).thenReturn(Optional.empty());

        var event = generateApiGatewayEvent(expectedCommonSubject);
        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ACCT_DOES_NOT_EXIST));
        verify(dynamoService, times(0)).updatePhoneNumber(EMAIL_ADDRESS, NEW_PHONE_NUMBER);
        verifyNoInteractions(sqsClient);
        verifyNoInteractions(auditService);
    }

    private APIGatewayProxyRequestEvent generateApiGatewayEvent(String principalId) {
        var event = new APIGatewayProxyRequestEvent();
        event.setBody(
                format(
                        "{\"email\": \"%s\", \"phoneNumber\": \"%s\", \"otp\": \"%s\"  }",
                        EMAIL_ADDRESS, NEW_PHONE_NUMBER, OTP));
        APIGatewayProxyRequestEvent.ProxyRequestContext proxyRequestContext =
                new APIGatewayProxyRequestEvent.ProxyRequestContext();
        Map<String, Object> authorizerParams = new HashMap<>();
        authorizerParams.put("principalId", principalId);
        proxyRequestContext.setAuthorizer(authorizerParams);
        proxyRequestContext.setIdentity(identityWithSourceIp("123.123.123.123"));
        event.setRequestContext(proxyRequestContext);
        event.setHeaders(
                Map.of(
                        PersistentIdHelper.PERSISTENT_ID_HEADER_NAME,
                        PERSISTENT_ID,
                        ClientSessionIdHelper.SESSION_ID_HEADER_NAME,
                        CLIENT_SESSION_ID,
                        AuditHelper.TXMA_ENCODED_HEADER_NAME,
                        TXMA_ENCODED_HEADER_VALUE));

        return event;
    }
}
