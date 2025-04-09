package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent;
import uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.ClientSession;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.NotificationType;
import uk.gov.di.authentication.shared.entity.NotifyRequest;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.UserCredentials;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethod;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.helpers.Argon2EncoderHelper;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.helpers.LocaleHelper.SupportedLanguage;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.helpers.SaltHelper;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthSessionService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.AwsSqsClient;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.CommonPasswordsService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoAccountModifiersService;
import uk.gov.di.authentication.shared.services.SerializationService;
import uk.gov.di.authentication.shared.services.SessionService;
import uk.gov.di.authentication.shared.validation.PasswordValidator;

import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_ACCOUNT_RECOVERY_BLOCK_ADDED;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_PASSWORD_RESET_SUCCESSFUL;
import static uk.gov.di.authentication.frontendapi.helpers.ApiGatewayProxyRequestHelper.apiRequestEventWithHeadersAndBody;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.CLIENT_SESSION_ID;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.DI_PERSISTENT_SESSION_ID;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.ENCODED_DEVICE_DETAILS;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.IP_ADDRESS;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.SESSION_ID;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.VALID_HEADERS;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.VALID_HEADERS_WITHOUT_AUDIT_ENCODED;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;
import static uk.gov.di.authentication.sharedtest.matchers.JsonArgumentMatcher.partiallyContainsJsonString;

class ResetPasswordHandlerTest {

    private final AuthenticationService authenticationService = mock(AuthenticationService.class);
    private final AwsSqsClient sqsClient = mock(AwsSqsClient.class);
    private final CodeStorageService codeStorageService = mock(CodeStorageService.class);
    private final SessionService sessionService = mock(SessionService.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final ClientService clientService = mock(ClientService.class);
    private final ClientSessionService clientSessionService = mock(ClientSessionService.class);
    private final ClientSession clientSession = mock(ClientSession.class);
    private final AuthSessionService authSessionService = mock(AuthSessionService.class);
    private final DynamoAccountModifiersService accountModifiersService =
            mock(DynamoAccountModifiersService.class);
    private static final Subject INTERNAL_SUBJECT_ID = new Subject();
    private static final byte[] SALT = SaltHelper.generateNewSalt();
    private final AuditService auditService = mock(AuditService.class);
    private final CommonPasswordsService commonPasswordsService =
            mock(CommonPasswordsService.class);
    private final PasswordValidator passwordValidator = mock(PasswordValidator.class);
    private final Context context = mock(Context.class);
    private static final String TEST_CLIENT_ID = "test-client-id";
    private static final String NEW_PASSWORD = CommonTestVariables.PASSWORD;
    private static final String SUBJECT = "some-subject";
    private static final String EMAIL = CommonTestVariables.EMAIL;
    private static final String INTERNAL_SECTOR_URI = "https://test.account.gov.uk";
    private static final Json objectMapper = SerializationService.getInstance();
    private static final NotifyRequest EXPECTED_SMS_NOTIFY_REQUEST =
            new NotifyRequest(
                    CommonTestVariables.UK_MOBILE_NUMBER,
                    NotificationType.PASSWORD_RESET_CONFIRMATION_SMS,
                    SupportedLanguage.EN,
                    SESSION_ID,
                    CLIENT_SESSION_ID);
    private static final NotifyRequest EXPECTED_EMAIL_NOTIFY_REQUEST =
            new NotifyRequest(
                    EMAIL,
                    NotificationType.PASSWORD_RESET_CONFIRMATION,
                    SupportedLanguage.EN,
                    SESSION_ID,
                    CLIENT_SESSION_ID);
    private final String expectedCommonSubject =
            ClientSubjectHelper.calculatePairwiseIdentifier(
                    INTERNAL_SUBJECT_ID.getValue(), "test.account.gov.uk", SALT);

    private final AuditContext auditContext =
            new AuditContext(
                    TEST_CLIENT_ID,
                    CLIENT_SESSION_ID,
                    SESSION_ID,
                    expectedCommonSubject,
                    EMAIL,
                    IP_ADDRESS,
                    AuditService.UNKNOWN,
                    DI_PERSISTENT_SESSION_ID,
                    Optional.of(ENCODED_DEVICE_DETAILS));

    private ResetPasswordHandler handler;
    private final Session session = new Session();
    private final AuthSessionItem authSession =
            new AuthSessionItem()
                    .withSessionId(SESSION_ID)
                    .withEmailAddress(EMAIL)
                    .withClientId(TEST_CLIENT_ID);

    private final ClientRegistry testClientRegistry =
            new ClientRegistry()
                    .withTestClient(true)
                    .withClientID(TEST_CLIENT_ID)
                    .withTestClientEmailAllowlist(
                            List.of(
                                    "joe.bloggs@digital.cabinet-office.gov.uk",
                                    EMAIL,
                                    "jb2@digital.cabinet-office.gov.uk"));

    @BeforeEach
    public void setUp() {
        doReturn(Optional.of(ErrorResponse.ERROR_1007))
                .when(passwordValidator)
                .validate("password");
        when(clientService.getClient(TEST_CLIENT_ID)).thenReturn(Optional.of(testClientRegistry));
        when(authenticationService.getOrGenerateSalt(any(UserProfile.class))).thenReturn(SALT);
        when(configurationService.getInternalSectorUri()).thenReturn(INTERNAL_SECTOR_URI);
        usingValidSession();
        usingValidClientSession();
        handler =
                new ResetPasswordHandler(
                        authenticationService,
                        sqsClient,
                        codeStorageService,
                        configurationService,
                        sessionService,
                        clientSessionService,
                        clientService,
                        auditService,
                        commonPasswordsService,
                        passwordValidator,
                        accountModifiersService,
                        authSessionService);
    }

    @Test
    void shouldReturn204ButNotPlaceMessageOnQueueForTestClient() {
        when(configurationService.isTestClientsEnabled()).thenReturn(true);
        when(authenticationService.getUserCredentialsFromEmail(EMAIL))
                .thenReturn(generateUserCredentials());
        when(authenticationService.getUserProfileByEmail(EMAIL))
                .thenReturn(generateUserProfile(false));
        var event = generateRequest(NEW_PASSWORD, VALID_HEADERS);

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(204));
        verifyNoInteractions(sqsClient);
        verify(authenticationService).updatePassword(EMAIL, NEW_PASSWORD);
        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.AUTH_PASSWORD_RESET_SUCCESSFUL_FOR_TEST_CLIENT,
                        auditContext);
    }

    @Test
    void checkAuditEventStillEmittedWhenTICFHeaderNotProvided() {
        when(configurationService.isTestClientsEnabled()).thenReturn(true);
        when(authenticationService.getUserCredentialsFromEmail(EMAIL))
                .thenReturn(generateUserCredentials());
        when(authenticationService.getUserProfileByEmail(EMAIL))
                .thenReturn(generateUserProfile(false));
        var event = generateRequest(NEW_PASSWORD, VALID_HEADERS_WITHOUT_AUDIT_ENCODED);

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(204));
        verifyNoInteractions(sqsClient);
        verify(authenticationService).updatePassword(EMAIL, NEW_PASSWORD);
        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.AUTH_PASSWORD_RESET_SUCCESSFUL_FOR_TEST_CLIENT,
                        auditContext.withTxmaAuditEncoded(Optional.empty()));
    }

    @Test
    void shouldReturn204ForSuccessfulRequestAndDontSendConfirmationToSMSWhenPhoneNumberNotVerified()
            throws Json.JsonException {
        when(authenticationService.getUserProfileByEmail(EMAIL))
                .thenReturn(generateUserProfile(false));
        when(authenticationService.getUserCredentialsFromEmail(EMAIL))
                .thenReturn(generateUserCredentials());
        var event = generateRequest(NEW_PASSWORD, VALID_HEADERS);

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(204));
        verify(sqsClient)
                .send(
                        argThat(
                                partiallyContainsJsonString(
                                        objectMapper.writeValueAsString(
                                                EXPECTED_EMAIL_NOTIFY_REQUEST),
                                        "unique_notification_reference")));
        verify(sqsClient, never())
                .send(objectMapper.writeValueAsString(EXPECTED_SMS_NOTIFY_REQUEST));
        verify(authenticationService).updatePassword(EMAIL, NEW_PASSWORD);
        verifyNoInteractions(accountModifiersService);
        verify(auditService).submitAuditEvent(AUTH_PASSWORD_RESET_SUCCESSFUL, auditContext);
    }

    @Test
    void
            shouldReturn204ForSuccessfulPasswordResetSendConfirmationToSMSAndUpdateModifiersTableWithBlock() {
        when(authenticationService.getUserCredentialsFromEmail(EMAIL))
                .thenReturn(generateUserCredentials());
        when(authenticationService.getUserProfileByEmail(EMAIL))
                .thenReturn(generateUserProfile(true));
        var event = generateRequest(NEW_PASSWORD, VALID_HEADERS);

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(204));
        verify(authenticationService).updatePassword(EMAIL, NEW_PASSWORD);
        verify(accountModifiersService).setAccountRecoveryBlock(expectedCommonSubject, true);
        verify(auditService).submitAuditEvent(AUTH_ACCOUNT_RECOVERY_BLOCK_ADDED, auditContext);
        verify(auditService).submitAuditEvent(AUTH_PASSWORD_RESET_SUCCESSFUL, auditContext);
    }

    private static Stream<Arguments> requestsToExpectedWriteToAccountModifersTable() {
        return Stream.of(
                Arguments.of(format("{ \"password\": \"%s\"}", NEW_PASSWORD), true),
                Arguments.of(
                        format(
                                "{ \"password\": \"%s\", \"allowMfaResetAfterPasswordReset\": false}",
                                NEW_PASSWORD),
                        true),
                Arguments.of(
                        format(
                                "{ \"password\": \"%s\", \"allowMfaResetAfterPasswordReset\": true}",
                                NEW_PASSWORD),
                        false));
    }

    @ParameterizedTest
    @MethodSource("requestsToExpectedWriteToAccountModifersTable")
    void
            shouldReturn204ForSuccessfulResetAndWriteToAccountModifiersTableDependentOnFlagPassedThroughInRequest(
                    String requestBody, boolean expectedWriteToAccountModifiers)
                    throws Json.JsonException {
        when(authenticationService.getUserCredentialsFromEmail(EMAIL))
                .thenReturn(generateUserCredentials());
        when(authenticationService.getUserProfileByEmail(EMAIL))
                .thenReturn(generateUserProfile(true));
        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, requestBody);

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(204));
        verify(sqsClient)
                .send(
                        argThat(
                                partiallyContainsJsonString(
                                        objectMapper.writeValueAsString(
                                                EXPECTED_EMAIL_NOTIFY_REQUEST),
                                        "unique_notification_reference")));
        verify(sqsClient)
                .send(
                        argThat(
                                partiallyContainsJsonString(
                                        objectMapper.writeValueAsString(
                                                EXPECTED_SMS_NOTIFY_REQUEST),
                                        "unique_notification_reference")));
        verify(authenticationService).updatePassword(EMAIL, NEW_PASSWORD);
        verify(auditService).submitAuditEvent(AUTH_PASSWORD_RESET_SUCCESSFUL, auditContext);

        if (expectedWriteToAccountModifiers) {
            verify(accountModifiersService).setAccountRecoveryBlock(expectedCommonSubject, true);
        } else {
            verify(accountModifiersService, never())
                    .setAccountRecoveryBlock(anyString(), anyBoolean());
        }
    }

    @Test
    void shouldReturn204ForSuccessfulMigratedUserRequestAndNoVerifiedMFAMethodIsPresent()
            throws Json.JsonException {
        when(authenticationService.getUserCredentialsFromEmail(EMAIL))
                .thenReturn(generateMigratedUserCredentials());
        when(authenticationService.getUserProfileByEmail(EMAIL))
                .thenReturn(generateUserProfile(false));
        var event = generateRequest(NEW_PASSWORD, VALID_HEADERS);

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(204));
        verify(sqsClient)
                .send(
                        argThat(
                                partiallyContainsJsonString(
                                        objectMapper.writeValueAsString(
                                                EXPECTED_EMAIL_NOTIFY_REQUEST),
                                        "unique_notification_reference")));
        verify(authenticationService).updatePassword(EMAIL, NEW_PASSWORD);
        verifyNoInteractions(accountModifiersService);
        verify(auditService).submitAuditEvent(AUTH_PASSWORD_RESET_SUCCESSFUL, auditContext);
    }

    @Test
    void shouldReturn400ForRequestIsMissingPassword() {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody("{ }");
        event.setHeaders(Map.of("Session-Id", SESSION_ID));

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1001));
        verifyNoInteractions(auditService);
        verifyNoInteractions(accountModifiersService);
    }

    @Test
    void shouldReturn400IfPasswordFailsValidation() {
        var event = generateRequest("password", VALID_HEADERS);

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1007));
        verify(authenticationService, never()).updatePassword(EMAIL, NEW_PASSWORD);
        verifyNoInteractions(auditService);
        verifyNoInteractions(accountModifiersService);
    }

    @Test
    void shouldReturn400IfNewPasswordEqualsExistingPassword() {
        when(authenticationService.getUserCredentialsFromEmail(EMAIL))
                .thenReturn(generateUserCredentials(Argon2EncoderHelper.argon2Hash(NEW_PASSWORD)));
        var event = generateRequest(NEW_PASSWORD, VALID_HEADERS);

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1024));
        verify(authenticationService, never()).updatePassword(EMAIL, NEW_PASSWORD);
        verifyNoInteractions(accountModifiersService);
        verifyNoInteractions(sqsClient);
        verifyNoInteractions(auditService);
    }

    @Test
    void shouldDeleteIncorrectPasswordCountOnSuccessfulRequest() throws Json.JsonException {
        when(authenticationService.getUserProfileByEmail(EMAIL))
                .thenReturn(generateUserProfile(false));
        when(authenticationService.getUserCredentialsFromEmail(EMAIL))
                .thenReturn(generateUserCredentials());
        when(codeStorageService.getIncorrectPasswordCount(EMAIL)).thenReturn(2);
        var event = generateRequest(NEW_PASSWORD, VALID_HEADERS);

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(204));
        verify(authenticationService).updatePassword(EMAIL, NEW_PASSWORD);
        verify(codeStorageService).deleteIncorrectPasswordCount(EMAIL);
        verify(sqsClient)
                .send(
                        argThat(
                                partiallyContainsJsonString(
                                        objectMapper.writeValueAsString(
                                                EXPECTED_EMAIL_NOTIFY_REQUEST),
                                        "unique_notification_reference")));
        verify(sqsClient, never())
                .send(objectMapper.writeValueAsString(EXPECTED_SMS_NOTIFY_REQUEST));
        verify(auditService).submitAuditEvent(AUTH_PASSWORD_RESET_SUCCESSFUL, auditContext);
    }

    @Test
    void shouldReturn400WhenUserHasInvalidSession() {
        when(sessionService.getSessionFromRequestHeaders(anyMap())).thenReturn(Optional.empty());
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("Session-Id", SESSION_ID));
        event.setBody(format("{ \"password\": \"%s\"}", NEW_PASSWORD));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1000));
        verify(authenticationService, never()).updatePassword(EMAIL, NEW_PASSWORD);
        verifyNoInteractions(auditService);
        verifyNoInteractions(accountModifiersService);
    }

    @Test
    void
            shouldUpdateAccountModifiersWithBlockWhenPasswordResetSuccessfullyAndVerifiedAuthAppIsPresent()
                    throws Json.JsonException {
        when(authenticationService.getUserProfileByEmail(EMAIL))
                .thenReturn(generateUserProfile(false));
        when(authenticationService.getUserCredentialsFromEmail(EMAIL))
                .thenReturn(generateUserCredentialsWithVerifiedAuthApp());

        var event = generateRequest(NEW_PASSWORD, VALID_HEADERS);
        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(204));
        verify(authenticationService).updatePassword(EMAIL, NEW_PASSWORD);
        verify(accountModifiersService).setAccountRecoveryBlock(expectedCommonSubject, true);
        verify(sqsClient)
                .send(
                        argThat(
                                partiallyContainsJsonString(
                                        objectMapper.writeValueAsString(
                                                EXPECTED_EMAIL_NOTIFY_REQUEST),
                                        "unique_notification_reference")));
        verify(sqsClient, never())
                .send(objectMapper.writeValueAsString(EXPECTED_SMS_NOTIFY_REQUEST));
        verify(auditService).submitAuditEvent(AUTH_ACCOUNT_RECOVERY_BLOCK_ADDED, auditContext);
        verify(auditService).submitAuditEvent(AUTH_PASSWORD_RESET_SUCCESSFUL, auditContext);
    }

    @Test
    void shouldRecordPasswordResetSuccessInSession() {
        when(authenticationService.getUserProfileByEmail(EMAIL))
                .thenReturn(generateUserProfile(false));
        when(authenticationService.getUserCredentialsFromEmail(EMAIL))
                .thenReturn(generateUserCredentialsWithVerifiedAuthApp());

        var event = generateRequest(NEW_PASSWORD, VALID_HEADERS);
        handler.handleRequest(event, context);

        verify(authSessionService)
                .updateSession(
                        argThat(
                                state ->
                                        state.getResetPasswordState()
                                                .equals(
                                                        AuthSessionItem.ResetPasswordState
                                                                .SUCCEEDED)));
    }

    private APIGatewayProxyRequestEvent generateRequest(
            String password, Map<String, String> headers) {
        var body = format("{ \"password\": \"%s\"}", password);
        return apiRequestEventWithHeadersAndBody(headers, body);
    }

    private void usingValidClientSession() {
        when(clientSessionService.getClientSessionFromRequestHeaders(anyMap()))
                .thenReturn(Optional.of(clientSession));
    }

    private UserCredentials generateUserCredentials() {
        return generateUserCredentials("old-password1");
    }

    private UserCredentials generateUserCredentials(String password) {
        return new UserCredentials().withEmail(EMAIL).withPassword(password).withSubjectID(SUBJECT);
    }

    private UserCredentials generateUserCredentialsWithVerifiedAuthApp() {
        return generateUserCredentials()
                .setMfaMethod(
                        new MFAMethod(
                                MFAMethodType.AUTH_APP.getValue(),
                                "auth-app-credential",
                                true,
                                true,
                                NowHelper.nowMinus(50, ChronoUnit.DAYS).toString()));
    }

    private UserProfile generateUserProfile(boolean isPhoneNumberVerified) {
        return new UserProfile()
                .withEmail(EMAIL)
                .withSubjectID(INTERNAL_SUBJECT_ID.getValue())
                .withPhoneNumber(CommonTestVariables.UK_MOBILE_NUMBER)
                .withPhoneNumberVerified(isPhoneNumberVerified);
    }

    private UserCredentials generateMigratedUserCredentials() {
        return new UserCredentials()
                .withEmail(EMAIL)
                .withSubjectID(INTERNAL_SUBJECT_ID.getValue())
                .withMigratedPassword("old-password1")
                .withSubjectID(SUBJECT);
    }

    private void usingValidSession() {
        when(sessionService.getSessionFromRequestHeaders(anyMap()))
                .thenReturn(Optional.of(session));
        when(authSessionService.getSessionFromRequestHeaders(anyMap()))
                .thenReturn(Optional.of(authSession));
    }
}
