package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.mockito.Mockito;
import software.amazon.awssdk.core.exception.SdkClientException;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent;
import uk.gov.di.authentication.frontendapi.entity.PasswordResetType;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.CredentialTrustLevel;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.NotificationType;
import uk.gov.di.authentication.shared.entity.NotifyRequest;
import uk.gov.di.authentication.shared.entity.PriorityIdentifier;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethod;
import uk.gov.di.authentication.shared.helpers.CommonTestVariables;
import uk.gov.di.authentication.shared.helpers.LocaleHelper.SupportedLanguage;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthSessionService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.AwsSqsClient;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.CodeGeneratorService;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.SerializationService;
import uk.gov.di.authentication.shared.services.mfa.MFAMethodsService;
import uk.gov.di.authentication.sharedtest.logging.CaptureLoggingExtension;
import uk.gov.di.authentication.userpermissions.PermissionDecisionManager;
import uk.gov.di.authentication.userpermissions.UserActionsManager;
import uk.gov.di.authentication.userpermissions.entity.Decision;
import uk.gov.di.authentication.userpermissions.entity.ForbiddenReason;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.frontendapi.helpers.ApiGatewayProxyRequestHelper.apiRequestEventWithHeadersAndBody;
import static uk.gov.di.authentication.shared.entity.NotificationType.RESET_PASSWORD_WITH_CODE;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.CLIENT_SESSION_ID;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.DI_PERSISTENT_SESSION_ID;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.EMAIL;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.ENCODED_DEVICE_DETAILS;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.INTERNAL_COMMON_SUBJECT_ID;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.IP_ADDRESS;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.SESSION_ID;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.VALID_HEADERS;
import static uk.gov.di.authentication.shared.helpers.TxmaAuditHelper.TXMA_AUDIT_ENCODED_HEADER;
import static uk.gov.di.authentication.shared.services.AuditService.MetadataPair.pair;
import static uk.gov.di.authentication.shared.services.mfa.MfaRetrieveFailureReason.USER_DOES_NOT_HAVE_ACCOUNT;
import static uk.gov.di.authentication.sharedtest.logging.LogEventMatcher.withMessageContaining;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;
import static uk.gov.di.authentication.sharedtest.matchers.JsonArgumentMatcher.partiallyContainsJsonString;

class ResetPasswordRequestHandlerTest {

    private static final String TEST_SIX_DIGIT_CODE = "123456";
    private static final long CODE_EXPIRY_TIME = 900;
    private static final String TEST_CLIENT_ID = "test-client-id";
    private static final long LOCKOUT_DURATION = 799;
    private static final Json objectMapper = SerializationService.getInstance();
    private static final AuditService.MetadataPair PASSWORD_RESET_COUNTER =
            pair("passwordResetCounter", 0);
    private static final AuditService.MetadataPair PASSWORD_RESET_TYPE_FORGOTTEN_PASSWORD =
            pair("passwordResetType", PasswordResetType.USER_FORGOTTEN_PASSWORD);

    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final AwsSqsClient awsSqsClient = mock(AwsSqsClient.class);
    private final AuthSessionService authSessionService = mock(AuthSessionService.class);
    private final CodeGeneratorService codeGeneratorService = mock(CodeGeneratorService.class);
    private final CodeStorageService codeStorageService = mock(CodeStorageService.class);
    private final AuthenticationService authenticationService = mock(AuthenticationService.class);
    private final ClientService clientService = mock(ClientService.class);
    private final AuditService auditService = mock(AuditService.class);
    private final MFAMethodsService mfaMethodsService = mock(MFAMethodsService.class);
    private final PermissionDecisionManager permissionDecisionManager =
            mock(PermissionDecisionManager.class);
    private final UserActionsManager userActionsManager = mock(UserActionsManager.class);
    private final Context context = mock(Context.class);
    private static final String CLIENT_ID = "test-client-id";

    private final ClientRegistry testClientRegistry =
            new ClientRegistry()
                    .withTestClient(true)
                    .withClientID(TEST_CLIENT_ID)
                    .withTestClientEmailAllowlist(
                            List.of(
                                    "joe.bloggs@digital.cabinet-office.gov.uk",
                                    CommonTestVariables.EMAIL,
                                    "jb2@digital.cabinet-office.gov.uk"));

    private final AuthSessionItem authSession =
            new AuthSessionItem()
                    .withSessionId(SESSION_ID)
                    .withEmailAddress(CommonTestVariables.EMAIL)
                    .withInternalCommonSubjectId(INTERNAL_COMMON_SUBJECT_ID)
                    .withClientId(CLIENT_ID)
                    .withRequestedCredentialStrength(CredentialTrustLevel.MEDIUM_LEVEL);
    private final ResetPasswordRequestHandler handler =
            new ResetPasswordRequestHandler(
                    configurationService,
                    clientService,
                    authenticationService,
                    awsSqsClient,
                    codeGeneratorService,
                    codeStorageService,
                    auditService,
                    authSessionService,
                    mfaMethodsService,
                    permissionDecisionManager,
                    userActionsManager);

    private final AuditContext auditContext =
            new AuditContext(
                    TEST_CLIENT_ID,
                    CLIENT_SESSION_ID,
                    SESSION_ID,
                    INTERNAL_COMMON_SUBJECT_ID,
                    CommonTestVariables.EMAIL,
                    IP_ADDRESS,
                    CommonTestVariables.UK_MOBILE_NUMBER,
                    DI_PERSISTENT_SESSION_ID,
                    Optional.of(ENCODED_DEVICE_DETAILS),
                    new ArrayList<>());

    @RegisterExtension
    public final CaptureLoggingExtension logging =
            new CaptureLoggingExtension(ResetPasswordRequestHandler.class);

    @AfterEach
    public void tearDown() {
        assertThat(
                logging.events(),
                not(hasItem(withMessageContaining(SESSION_ID, CommonTestVariables.EMAIL))));
    }

    @BeforeEach
    void setup() {
        when(clientService.getClient(TEST_CLIENT_ID)).thenReturn(Optional.of(testClientRegistry));
        when(configurationService.getDefaultOtpCodeExpiry()).thenReturn(CODE_EXPIRY_TIME);
        when(codeGeneratorService.twentyByteEncodedRandomCode()).thenReturn(TEST_SIX_DIGIT_CODE);
        when(codeGeneratorService.sixDigitCode()).thenReturn(TEST_SIX_DIGIT_CODE);
        when(configurationService.getCodeMaxRetries()).thenReturn(6);
        when(permissionDecisionManager.canSendEmailOtpNotification(any(), any()))
                .thenReturn(Result.success(new Decision.Permitted(0)));
        when(permissionDecisionManager.canVerifyEmailOtp(any(), any()))
                .thenReturn(Result.success(new Decision.Permitted(0)));
        when(userActionsManager.sentEmailOtpNotification(any(), any()))
                .thenReturn(Result.success(null));
    }

    @Nested
    class WhenTheRequestIsValid {

        static final String VALID_REQUEST_BODY =
                format("{ \"email\": \"%s\"}", CommonTestVariables.EMAIL);
        static NotifyRequest notifyRequest =
                new NotifyRequest(
                        CommonTestVariables.EMAIL,
                        RESET_PASSWORD_WITH_CODE,
                        TEST_SIX_DIGIT_CODE,
                        SupportedLanguage.EN,
                        SESSION_ID,
                        CLIENT_SESSION_ID);

        public static APIGatewayProxyRequestEvent validEvent;

        @BeforeEach
        void setup() {
            validEvent = apiRequestEventWithHeadersAndBody(VALID_HEADERS, VALID_REQUEST_BODY);
            Subject subject = new Subject("subject_1");
            when(authenticationService.getSubjectFromEmail(CommonTestVariables.EMAIL))
                    .thenReturn(subject);
            when(authenticationService.getPhoneNumber(CommonTestVariables.EMAIL))
                    .thenReturn(Optional.of(CommonTestVariables.UK_MOBILE_NUMBER));
            var disabledMfaMethod =
                    MFAMethod.authAppMfaMethod(
                            "first-value",
                            true,
                            false,
                            PriorityIdentifier.BACKUP,
                            "auth-app-mfa-id");
            var enabledMfaMethod =
                    MFAMethod.smsMfaMethod(
                            true,
                            true,
                            CommonTestVariables.UK_MOBILE_NUMBER,
                            PriorityIdentifier.DEFAULT,
                            "sms-mfa-id");
            when(mfaMethodsService.getMfaMethods(CommonTestVariables.EMAIL))
                    .thenReturn(Result.success(List.of(disabledMfaMethod, enabledMfaMethod)));
        }

        @Test
        void shouldReturn200WithTheUsersMfaMethodAndSaveOtpCodeForAValidRequest() {
            usingValidSession();
            APIGatewayProxyResponseEvent result = handler.handleRequest(validEvent, context);

            assertEquals(200, result.getStatusCode());
            var expectedBody =
                    "{\"mfaMethodType\":\"SMS\",\"mfaMethods\":[{\"id\":\"auth-app-mfa-id\",\"type\":\"AUTH_APP\",\"priority\":\"BACKUP\"},{\"id\":\"sms-mfa-id\",\"type\":\"SMS\",\"priority\":\"DEFAULT\",\"redactedPhoneNumber\":\"*********7890\"}],\"phoneNumberLastThree\":\"890\"}";
            assertEquals(expectedBody, result.getBody());
            verify(codeStorageService)
                    .saveOtpCode(
                            CommonTestVariables.EMAIL,
                            TEST_SIX_DIGIT_CODE,
                            CODE_EXPIRY_TIME,
                            RESET_PASSWORD_WITH_CODE);
            verify(authSessionService, atLeastOnce()).updateSession(any(AuthSessionItem.class));
        }

        @Test
        void shouldReturn200WithTheMigratedUsersMfaMethodAndSaveOtpCodeForAValidRequest() {
            usingValidSession();
            when(mfaMethodsService.getMfaMethods(CommonTestVariables.EMAIL))
                    .thenReturn(
                            Result.success(
                                    List.of(
                                            MFAMethod.smsMfaMethod(
                                                    true,
                                                    true,
                                                    CommonTestVariables.UK_MOBILE_NUMBER,
                                                    PriorityIdentifier.DEFAULT,
                                                    "1"))));

            APIGatewayProxyResponseEvent result = handler.handleRequest(validEvent, context);

            assertEquals(200, result.getStatusCode());
            var expectedBody =
                    "{\"mfaMethodType\":\"SMS\",\"mfaMethods\":[{\"id\":\"1\",\"type\":\"SMS\",\"priority\":\"DEFAULT\",\"redactedPhoneNumber\":\"*********7890\"}],\"phoneNumberLastThree\":\"890\"}";
            assertEquals(expectedBody, result.getBody());
            verify(codeStorageService)
                    .saveOtpCode(
                            CommonTestVariables.EMAIL,
                            TEST_SIX_DIGIT_CODE,
                            CODE_EXPIRY_TIME,
                            RESET_PASSWORD_WITH_CODE);
            verify(authSessionService, atLeastOnce()).updateSession(any(AuthSessionItem.class));
        }

        @Test
        void shouldReturn200WithTheMigratedUsersMfaMethodAndSaveEmailOtpCodeForAValidRequest() {
            usingValidSession();
            when(mfaMethodsService.getMfaMethods(CommonTestVariables.EMAIL))
                    .thenReturn(
                            Result.success(
                                    List.of(
                                            MFAMethod.authAppMfaMethod(
                                                    "cred",
                                                    true,
                                                    true,
                                                    PriorityIdentifier.DEFAULT,
                                                    "auth-app-id"))));

            APIGatewayProxyResponseEvent result = handler.handleRequest(validEvent, context);

            assertEquals(200, result.getStatusCode());
            var expectedBody =
                    "{\"mfaMethodType\":\"AUTH_APP\",\"mfaMethods\":[{\"id\":\"auth-app-id\",\"type\":\"AUTH_APP\",\"priority\":\"DEFAULT\"}],\"phoneNumberLastThree\":null}";
            assertEquals(expectedBody, result.getBody());
            verify(codeStorageService)
                    .saveOtpCode(
                            CommonTestVariables.EMAIL,
                            TEST_SIX_DIGIT_CODE,
                            CODE_EXPIRY_TIME,
                            RESET_PASSWORD_WITH_CODE);
            verify(authSessionService, atLeastOnce()).updateSession(any(AuthSessionItem.class));
        }

        @Test
        void shouldPutMessageOnQueueForAValidCodeFlowRequest() throws Json.JsonException {
            usingValidSession();

            APIGatewayProxyResponseEvent result = handler.handleRequest(validEvent, context);

            assertEquals(200, result.getStatusCode());
            verify(awsSqsClient)
                    .send(
                            argThat(
                                    partiallyContainsJsonString(
                                            objectMapper.writeValueAsString(notifyRequest),
                                            "unique_notification_reference")));
        }

        @Test
        void shouldSubmitCorrectAuditEventForAValidRequest() {
            usingValidSession();

            handler.handleRequest(validEvent, context);

            verify(auditService)
                    .submitAuditEvent(
                            FrontendAuditableEvent.AUTH_PASSWORD_RESET_REQUESTED,
                            auditContext,
                            PASSWORD_RESET_COUNTER,
                            PASSWORD_RESET_TYPE_FORGOTTEN_PASSWORD);
        }

        @Test
        void checkPasswordResetRequestedAuditEventStillEmittedWhenTICFHeaderNotProvided() {
            usingValidSession();
            var headers = validEvent.getHeaders();
            var headersWithoutTICF =
                    headers.entrySet().stream()
                            .filter(entry -> !entry.getKey().equals(TXMA_AUDIT_ENCODED_HEADER))
                            .collect(
                                    Collectors.toUnmodifiableMap(
                                            Map.Entry::getKey, Map.Entry::getValue));
            validEvent.setHeaders(headersWithoutTICF);

            handler.handleRequest(validEvent, context);

            verify(auditService)
                    .submitAuditEvent(
                            FrontendAuditableEvent.AUTH_PASSWORD_RESET_REQUESTED,
                            auditContext.withTxmaAuditEncoded(Optional.empty()),
                            PASSWORD_RESET_COUNTER,
                            PASSWORD_RESET_TYPE_FORGOTTEN_PASSWORD);
        }

        @Test
        void shouldUseExistingOtpCodeIfOneExists() throws Json.JsonException {
            when(codeStorageService.getOtpCode(any(String.class), any(NotificationType.class)))
                    .thenReturn(Optional.of(TEST_SIX_DIGIT_CODE));

            usingValidSession();
            APIGatewayProxyResponseEvent result = handler.handleRequest(validEvent, context);

            verify(codeGeneratorService, never()).sixDigitCode();
            verify(codeStorageService, never())
                    .saveOtpCode(
                            any(String.class),
                            any(String.class),
                            anyLong(),
                            any(NotificationType.class));
            verify(awsSqsClient)
                    .send(
                            argThat(
                                    partiallyContainsJsonString(
                                            objectMapper.writeValueAsString(notifyRequest),
                                            "unique_notification_reference")));
            assertThat(result, hasStatus(200));
        }

        @Test
        void shouldReturn200ButNotPutMessageOnQueueIfTestClient() {
            when(configurationService.isTestClientsEnabled()).thenReturn(true);

            usingValidSession();
            var result = handler.handleRequest(validEvent, context);

            assertEquals(200, result.getStatusCode());

            verifyNoInteractions(awsSqsClient);
            verify(codeStorageService)
                    .saveOtpCode(
                            CommonTestVariables.EMAIL,
                            TEST_SIX_DIGIT_CODE,
                            CODE_EXPIRY_TIME,
                            RESET_PASSWORD_WITH_CODE);
            verify(authSessionService, atLeastOnce()).updateSession(any(AuthSessionItem.class));
            verify(auditService)
                    .submitAuditEvent(
                            FrontendAuditableEvent.AUTH_PASSWORD_RESET_REQUESTED_FOR_TEST_CLIENT,
                            auditContext,
                            PASSWORD_RESET_COUNTER,
                            PASSWORD_RESET_TYPE_FORGOTTEN_PASSWORD);
        }

        @Test
        void
                checkPasswordResetRequestedForTestClientAuditEventStillEmittedWhenTICFHeaderNotProvided() {
            when(configurationService.isTestClientsEnabled()).thenReturn(true);
            usingValidSession();
            var headers = validEvent.getHeaders();
            var headersWithoutTICF =
                    headers.entrySet().stream()
                            .filter(entry -> !entry.getKey().equals(TXMA_AUDIT_ENCODED_HEADER))
                            .collect(
                                    Collectors.toUnmodifiableMap(
                                            Map.Entry::getKey, Map.Entry::getValue));
            validEvent.setHeaders(headersWithoutTICF);

            var result = handler.handleRequest(validEvent, context);

            assertEquals(200, result.getStatusCode());

            verify(auditService)
                    .submitAuditEvent(
                            FrontendAuditableEvent.AUTH_PASSWORD_RESET_REQUESTED_FOR_TEST_CLIENT,
                            auditContext.withTxmaAuditEncoded(Optional.empty()),
                            PASSWORD_RESET_COUNTER,
                            PASSWORD_RESET_TYPE_FORGOTTEN_PASSWORD);
        }

        @Test
        void shouldRecordPasswordResetAttemptInSession() {
            usingValidSession();
            when(mfaMethodsService.getMfaMethods(EMAIL)).thenReturn(Result.success(List.of()));

            handler.handleRequest(validEvent, context);

            verify(authSessionService, atLeastOnce())
                    .updateSession(
                            argThat(
                                    s ->
                                            s.getResetPasswordState() != null
                                                    && s.getResetPasswordState()
                                                            .equals(
                                                                    AuthSessionItem
                                                                            .ResetPasswordState
                                                                            .ATTEMPTED)));
        }

        @Test
        void shouldReturn404IfUserProfileIsNotFound() {
            usingValidSession();
            when(mfaMethodsService.getMfaMethods(CommonTestVariables.EMAIL))
                    .thenReturn(Result.failure(USER_DOES_NOT_HAVE_ACCOUNT));
            var result = handler.handleRequest(validEvent, context);

            assertEquals(404, result.getStatusCode());
            assertThat(result, hasJsonBody(ErrorResponse.USER_NOT_FOUND));
        }

        @Test
        void shouldReturn400IfUserIsBlockedFromRequestingAnyMorePasswordResets() {
            usingSessionWithPasswordResetCount(0);
            when(permissionDecisionManager.canSendEmailOtpNotification(any(), any()))
                    .thenReturn(
                            Result.success(
                                    new Decision.TemporarilyLockedOut(
                                            ForbiddenReason.BLOCKED_FOR_PW_RESET_REQUEST,
                                            0,
                                            Instant.now(),
                                            false)));

            var result = handler.handleRequest(validEvent, context);

            assertEquals(400, result.getStatusCode());
            assertThat(result, hasJsonBody(ErrorResponse.BLOCKED_FOR_PW_RESET_REQUEST));
            verifyNoInteractions(awsSqsClient);
        }

        @Test
        void shouldReturn400IfUserIsBlockedFromEnteringAnyMoreInvalidPasswordResetsOTPs() {
            usingSessionWithPasswordResetCount(0);
            when(permissionDecisionManager.canVerifyEmailOtp(any(), any()))
                    .thenReturn(
                            Result.success(
                                    new Decision.TemporarilyLockedOut(
                                            ForbiddenReason
                                                    .EXCEEDED_INCORRECT_EMAIL_OTP_SUBMISSION_LIMIT,
                                            0,
                                            Instant.now(),
                                            false)));

            var result = handler.handleRequest(validEvent, context);

            assertEquals(400, result.getStatusCode());
            assertThat(result, hasJsonBody(ErrorResponse.TOO_MANY_INVALID_PW_RESET_CODES_ENTERED));
            verifyNoInteractions(awsSqsClient);
        }

        @Test
        void shouldReturn400IfUserIsNewlyBlockedFromEnteringAnyMoreInvalidPasswordResetsOTPs() {
            when(configurationService.getCodeMaxRetries()).thenReturn(6);
            usingSessionWithPasswordResetCount(5);
            // First call returns permitted, second call (after increment) returns locked out
            when(permissionDecisionManager.canSendEmailOtpNotification(any(), any()))
                    .thenReturn(Result.success(new Decision.Permitted(5)))
                    .thenReturn(
                            Result.success(
                                    new Decision.TemporarilyLockedOut(
                                            ForbiddenReason
                                                    .EXCEEDED_SEND_EMAIL_OTP_NOTIFICATION_LIMIT,
                                            6,
                                            Instant.now(),
                                            true)));
            when(permissionDecisionManager.canVerifyEmailOtp(any(), any()))
                    .thenReturn(Result.success(new Decision.Permitted(0)));

            var result = handler.handleRequest(validEvent, context);

            assertEquals(400, result.getStatusCode());
            assertThat(result, hasJsonBody(ErrorResponse.TOO_MANY_PW_RESET_REQUESTS));
            verifyNoInteractions(awsSqsClient);
        }

        @Test
        void shouldReturn500IfMessageCannotBeSentToQueue() throws Json.JsonException {
            Mockito.doThrow(SdkClientException.class)
                    .when(awsSqsClient)
                    .send(
                            argThat(
                                    partiallyContainsJsonString(
                                            objectMapper.writeValueAsString(notifyRequest),
                                            "unique_notification_reference")));

            usingValidSession();
            APIGatewayProxyResponseEvent result = handler.handleRequest(validEvent, context);

            assertEquals(500, result.getStatusCode());
            assertTrue(result.getBody().contains("Error sending message to queue"));
        }

        @Test
        void shouldReturn400IfUserHasExceededPasswordResetRequestCount() {
            when(configurationService.getLockoutDuration()).thenReturn(LOCKOUT_DURATION);
            usingSessionWithPasswordResetCount(6);
            when(permissionDecisionManager.canSendEmailOtpNotification(any(), any()))
                    .thenReturn(
                            Result.success(
                                    new Decision.TemporarilyLockedOut(
                                            ForbiddenReason
                                                    .EXCEEDED_SEND_EMAIL_OTP_NOTIFICATION_LIMIT,
                                            6,
                                            Instant.now(),
                                            false)));

            APIGatewayProxyResponseEvent result = handler.handleRequest(validEvent, context);

            assertEquals(400, result.getStatusCode());
            assertThat(result, hasJsonBody(ErrorResponse.BLOCKED_FOR_PW_RESET_REQUEST));
            verifyNoInteractions(awsSqsClient);
        }

        @Test
        void shouldReturn400WithTooManyRequestsWhenFirstTimeLimit() {
            when(configurationService.getLockoutDuration()).thenReturn(LOCKOUT_DURATION);
            usingSessionWithPasswordResetCount(5);
            when(permissionDecisionManager.canSendEmailOtpNotification(any(), any()))
                    .thenReturn(
                            Result.success(
                                    new Decision.TemporarilyLockedOut(
                                            ForbiddenReason
                                                    .EXCEEDED_SEND_EMAIL_OTP_NOTIFICATION_LIMIT,
                                            5,
                                            Instant.now(),
                                            true)));

            APIGatewayProxyResponseEvent result = handler.handleRequest(validEvent, context);

            assertEquals(400, result.getStatusCode());
            assertThat(result, hasJsonBody(ErrorResponse.TOO_MANY_PW_RESET_REQUESTS));
            verifyNoInteractions(awsSqsClient);
        }

        @Test
        void shouldReturn400WithBlockedWhenSubsequentRequest() {
            when(configurationService.getLockoutDuration()).thenReturn(LOCKOUT_DURATION);
            usingSessionWithPasswordResetCount(6);
            when(permissionDecisionManager.canSendEmailOtpNotification(any(), any()))
                    .thenReturn(
                            Result.success(
                                    new Decision.TemporarilyLockedOut(
                                            ForbiddenReason
                                                    .EXCEEDED_SEND_EMAIL_OTP_NOTIFICATION_LIMIT,
                                            6,
                                            Instant.now(),
                                            false)));

            APIGatewayProxyResponseEvent result = handler.handleRequest(validEvent, context);

            assertEquals(400, result.getStatusCode());
            assertThat(result, hasJsonBody(ErrorResponse.BLOCKED_FOR_PW_RESET_REQUEST));
            verifyNoInteractions(awsSqsClient);
        }

        @Test
        void shouldReturn400WhenNoEmailIsPresentInSession() {
            when(authenticationService.getPhoneNumber(CommonTestVariables.EMAIL))
                    .thenReturn(Optional.of(CommonTestVariables.UK_MOBILE_NUMBER));
            when(authSessionService.getSessionFromRequestHeaders(anyMap()))
                    .thenReturn(Optional.of(new AuthSessionItem().withSessionId(SESSION_ID)));

            APIGatewayProxyResponseEvent result = handler.handleRequest(validEvent, context);

            assertEquals(400, result.getStatusCode());
            verifyNoInteractions(awsSqsClient);
            verifyNoInteractions(codeStorageService);
            verifyNoInteractions(auditService);
        }
    }

    @Nested
    class WhenRequestIsInvalid {
        @Test
        void shouldReturn400IfInvalidSessionProvided() {
            var body = format("{ \"email\": \"%s\" }", CommonTestVariables.EMAIL);
            APIGatewayProxyRequestEvent event = apiRequestEventWithHeadersAndBody(Map.of(), body);
            APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

            assertEquals(400, result.getStatusCode());

            verify(awsSqsClient, never()).send(anyString());
            verify(codeStorageService, never())
                    .saveOtpCode(anyString(), anyString(), anyLong(), any(NotificationType.class));
            verifyNoInteractions(awsSqsClient);
        }

        @Test
        void shouldReturn400IfRequestIsMissingEmail() {
            usingValidSession();
            var body = "{ }";
            APIGatewayProxyRequestEvent event =
                    apiRequestEventWithHeadersAndBody(VALID_HEADERS, body);
            APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

            assertEquals(400, result.getStatusCode());
            assertThat(result, hasJsonBody(ErrorResponse.REQUEST_MISSING_PARAMS));
            verifyNoInteractions(awsSqsClient);
        }

        @Test
        void shouldReturn400IfRequestIsForDifferentEmail() {
            usingValidSession();
            var body = format("{ \"email\": \"%s\" }", "different-email@gov.uk");
            APIGatewayProxyRequestEvent event =
                    apiRequestEventWithHeadersAndBody(VALID_HEADERS, body);
            APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

            assertEquals(400, result.getStatusCode());
            assertThat(result, hasJsonBody(ErrorResponse.SESSION_ID_MISSING));
            verifyNoInteractions(awsSqsClient);
        }
    }

    private void usingValidSession() {
        when(authSessionService.getSessionFromRequestHeaders(anyMap()))
                .thenReturn(Optional.of(authSession));
    }

    private void usingSessionWithPasswordResetCount(int passwordResetCount) {
        authSession.resetPasswordResetCount();
        IntStream.range(0, passwordResetCount)
                .forEach((i) -> authSession.incrementPasswordResetCount());
        when(authSessionService.getSessionFromRequestHeaders(anyMap()))
                .thenReturn(Optional.of(authSession));
    }
}
