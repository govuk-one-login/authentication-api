package uk.gov.di.accountmanagement.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.accountmanagement.domain.AccountManagementAuditableEvent;
import uk.gov.di.accountmanagement.entity.NotificationType;
import uk.gov.di.accountmanagement.entity.NotifyRequest;
import uk.gov.di.accountmanagement.exceptions.InvalidPrincipalException;
import uk.gov.di.accountmanagement.helpers.AuditHelper;
import uk.gov.di.accountmanagement.services.AwsSqsClient;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.UserCredentials;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.helpers.Argon2EncoderHelper;
import uk.gov.di.authentication.shared.helpers.ClientSessionIdHelper;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.helpers.LocaleHelper.SupportedLanguage;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.helpers.SaltHelper;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.CommonPasswordsService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.SerializationService;
import uk.gov.di.authentication.shared.validation.PasswordValidator;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.di.accountmanagement.constants.AccountManagementConstants.AUDIT_EVENT_COMPONENT_ID_AUTH;
import static uk.gov.di.authentication.sharedtest.helper.RequestEventHelper.identityWithSourceIp;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class UpdatePasswordHandlerTest {

    private final Context context = mock(Context.class);
    private final DynamoService dynamoService = mock(DynamoService.class);
    private final AwsSqsClient sqsClient = mock(AwsSqsClient.class);
    private final AuditService auditService = mock(AuditService.class);
    private final CommonPasswordsService commonPasswordsService =
            mock(CommonPasswordsService.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final PasswordValidator passwordValidator = mock(PasswordValidator.class);

    private UpdatePasswordHandler handler;
    private static final String EXISTING_EMAIL_ADDRESS = "joe.bloggs@digital.cabinet-office.gov.uk";
    private static final String NEW_PASSWORD = "password2";
    private static final String CURRENT_PASSWORD = "password1";
    private static final String INVALID_PASSWORD = "pwd";
    private static final byte[] SALT = SaltHelper.generateNewSalt();
    private static final String PERSISTENT_ID = "some-persistent-session-id";
    private static final String SESSION_ID = "some-session-id";
    private static final String CLIENT_ID = "some-client-id";
    private static final Subject INTERNAL_SUBJECT = new Subject();
    private static final String TXMA_ENCODED_HEADER_VALUE = "txma-test-value";
    private final String expectedCommonSubject =
            ClientSubjectHelper.calculatePairwiseIdentifier(
                    INTERNAL_SUBJECT.getValue(), "test.account.gov.uk", SALT);
    private final Json objectMapper = SerializationService.getInstance();

    @BeforeEach
    void setUp() {
        handler =
                new UpdatePasswordHandler(
                        dynamoService,
                        sqsClient,
                        auditService,
                        commonPasswordsService,
                        passwordValidator,
                        configurationService);
        when(configurationService.getInternalSectorUri()).thenReturn("https://test.account.gov.uk");
        when(dynamoService.getOrGenerateSalt(any(UserProfile.class))).thenReturn(SALT);
    }

    @Test
    void shouldReturn204WhenPrincipalContainsInternalPairwiseSubjectId() throws Json.JsonException {
        var userProfile = new UserProfile().withSubjectID(INTERNAL_SUBJECT.getValue());
        var userCredentials = new UserCredentials().withPassword(CURRENT_PASSWORD);
        when(dynamoService.getUserProfileByEmailMaybe(EXISTING_EMAIL_ADDRESS))
                .thenReturn(Optional.of(userProfile));
        when(dynamoService.getUserCredentialsFromEmail(EXISTING_EMAIL_ADDRESS))
                .thenReturn(userCredentials);

        var event = generateApiGatewayEvent(NEW_PASSWORD, expectedCommonSubject);
        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(204));
        verify(dynamoService).updatePassword(EXISTING_EMAIL_ADDRESS, NEW_PASSWORD);
        verify(sqsClient)
                .send(
                        objectMapper.writeValueAsString(
                                new NotifyRequest(
                                        EXISTING_EMAIL_ADDRESS,
                                        NotificationType.PASSWORD_UPDATED,
                                        SupportedLanguage.EN)));
        verify(auditService)
                .submitAuditEvent(
                        AccountManagementAuditableEvent.AUTH_UPDATE_PASSWORD,
                        new AuditContext(
                                CLIENT_ID,
                                SESSION_ID,
                                AuditService.UNKNOWN,
                                expectedCommonSubject,
                                userProfile.getEmail(),
                                "123.123.123.123",
                                userProfile.getPhoneNumber(),
                                PERSISTENT_ID,
                                Optional.of(TXMA_ENCODED_HEADER_VALUE),
                                new ArrayList<>()),
                        AUDIT_EVENT_COMPONENT_ID_AUTH);
    }

    @Test
    void shouldThrowIfPrincipalIdIsInvalid() {
        var userProfile = new UserProfile().withSubjectID(new Subject().getValue());
        when(dynamoService.getUserProfileByEmailMaybe(EXISTING_EMAIL_ADDRESS))
                .thenReturn(Optional.of(userProfile));
        when(dynamoService.getOrGenerateSalt(userProfile)).thenReturn(SaltHelper.generateNewSalt());

        var event = generateApiGatewayEvent(NEW_PASSWORD, expectedCommonSubject);

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
    void shouldReturn400WhenRequestHasIncorrectParameters() {
        APIGatewayProxyRequestEvent.ProxyRequestContext proxyRequestContext =
                new APIGatewayProxyRequestEvent.ProxyRequestContext();
        Map<String, Object> authorizerParams = new HashMap<>();
        authorizerParams.put("principalId", expectedCommonSubject);
        proxyRequestContext.setAuthorizer(authorizerParams);
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setRequestContext(proxyRequestContext);
        event.setBody(
                format("{ \"incorrect\": \"%s\", \"parameter\": \"%s\"}", "incorrect", "value"));
        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.REQUEST_MISSING_PARAMS));
        verifyNoInteractions(auditService);
        verifyNoInteractions(sqsClient);
    }

    @Test
    void shouldReturn400WhenNewPasswordEqualsExistingPassword() {
        var userProfile = new UserProfile().withSubjectID(INTERNAL_SUBJECT.getValue());
        var userCredentials =
                new UserCredentials().withPassword(Argon2EncoderHelper.argon2Hash(NEW_PASSWORD));
        when(dynamoService.getUserProfileByEmailMaybe(EXISTING_EMAIL_ADDRESS))
                .thenReturn(Optional.of(userProfile));
        when(dynamoService.getUserCredentialsFromEmail(EXISTING_EMAIL_ADDRESS))
                .thenReturn(userCredentials);

        var event = generateApiGatewayEvent(NEW_PASSWORD, expectedCommonSubject);
        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.NEW_PW_MATCHES_OLD));
        verify(dynamoService, never()).updatePassword(EXISTING_EMAIL_ADDRESS, NEW_PASSWORD);
        verifyNoInteractions(sqsClient);
        verifyNoInteractions(auditService);
    }

    @Test
    void shouldReturn400IfUserAccountDoesNotExistForCurrentEmail() {
        when(dynamoService.getUserProfileByEmailMaybe(EXISTING_EMAIL_ADDRESS))
                .thenReturn(Optional.empty());

        var event = generateApiGatewayEvent(NEW_PASSWORD, expectedCommonSubject);
        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ACCT_DOES_NOT_EXIST));
        verify(dynamoService, never()).updatePassword(EXISTING_EMAIL_ADDRESS, NEW_PASSWORD);
        verifyNoInteractions(sqsClient);
        verifyNoInteractions(auditService);
    }

    @Test
    void shouldReturn400WhenPasswordValidationFails() {
        doReturn(Optional.of(ErrorResponse.INVALID_PW_LENGTH))
                .when(passwordValidator)
                .validate(INVALID_PASSWORD);

        var event = generateApiGatewayEvent(INVALID_PASSWORD, expectedCommonSubject);
        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.INVALID_PW_LENGTH));
        verify(dynamoService, never()).updatePassword(EXISTING_EMAIL_ADDRESS, NEW_PASSWORD);
        verifyNoInteractions(auditService);
    }

    private APIGatewayProxyRequestEvent generateApiGatewayEvent(
            String newPassword, String principalId) {
        var event = new APIGatewayProxyRequestEvent();
        event.setBody(
                format(
                        "{\"email\": \"%s\", \"newPassword\": \"%s\" }",
                        EXISTING_EMAIL_ADDRESS, newPassword));
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
