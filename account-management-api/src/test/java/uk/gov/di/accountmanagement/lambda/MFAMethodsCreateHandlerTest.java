package uk.gov.di.accountmanagement.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.google.gson.JsonParser;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;
import uk.gov.di.accountmanagement.entity.NotificationType;
import uk.gov.di.accountmanagement.entity.NotifyRequest;
import uk.gov.di.accountmanagement.helpers.AuditHelper;
import uk.gov.di.accountmanagement.services.AwsSqsClient;
import uk.gov.di.accountmanagement.services.CodeStorageService;
import uk.gov.di.accountmanagement.services.MfaMethodsMigrationService;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.PriorityIdentifier;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethod;
import uk.gov.di.authentication.shared.entity.mfa.MfaDetail;
import uk.gov.di.authentication.shared.entity.mfa.request.MfaMethodCreateRequest;
import uk.gov.di.authentication.shared.entity.mfa.request.RequestAuthAppMfaDetail;
import uk.gov.di.authentication.shared.entity.mfa.request.RequestSmsMfaDetail;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.helpers.LocaleHelper;
import uk.gov.di.authentication.shared.helpers.SaltHelper;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.SerializationService;
import uk.gov.di.authentication.shared.services.mfa.MFAMethodsService;
import uk.gov.di.authentication.shared.services.mfa.MfaCreateFailureReason;
import uk.gov.di.authentication.sharedtest.logging.CaptureLoggingExtension;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasItem;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.di.accountmanagement.constants.AccountManagementConstants.AUDIT_EVENT_COMPONENT_ID_HOME;
import static uk.gov.di.accountmanagement.domain.AccountManagementAuditableEvent.AUTH_CODE_VERIFIED;
import static uk.gov.di.accountmanagement.domain.AccountManagementAuditableEvent.AUTH_INVALID_CODE_SENT;
import static uk.gov.di.accountmanagement.domain.AccountManagementAuditableEvent.AUTH_MFA_METHOD_ADD_COMPLETED;
import static uk.gov.di.accountmanagement.domain.AccountManagementAuditableEvent.AUTH_MFA_METHOD_ADD_FAILED;
import static uk.gov.di.accountmanagement.domain.AccountManagementAuditableEvent.AUTH_UPDATE_PHONE_NUMBER;
import static uk.gov.di.accountmanagement.helpers.CommonTestVariables.IP_ADDRESS;
import static uk.gov.di.accountmanagement.helpers.CommonTestVariables.PERSISTENT_ID;
import static uk.gov.di.accountmanagement.helpers.CommonTestVariables.SESSION_ID;
import static uk.gov.di.accountmanagement.helpers.CommonTestVariables.TXMA_ENCODED_HEADER_VALUE;
import static uk.gov.di.accountmanagement.helpers.CommonTestVariables.VALID_HEADERS;
import static uk.gov.di.authentication.shared.domain.RequestHeaders.SESSION_ID_HEADER;
import static uk.gov.di.authentication.shared.entity.JourneyType.ACCOUNT_MANAGEMENT;
import static uk.gov.di.authentication.shared.entity.NotificationType.MFA_SMS;
import static uk.gov.di.authentication.shared.entity.PriorityIdentifier.BACKUP;
import static uk.gov.di.authentication.shared.entity.PriorityIdentifier.DEFAULT;
import static uk.gov.di.authentication.shared.entity.mfa.MFAMethodType.AUTH_APP;
import static uk.gov.di.authentication.shared.entity.mfa.MFAMethodType.SMS;
import static uk.gov.di.authentication.shared.services.AuditService.MetadataPair.pair;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.INTERNATIONAL_MOBILE_NUMBER;
import static uk.gov.di.authentication.sharedtest.helper.RequestEventHelper.identityWithSourceIp;
import static uk.gov.di.authentication.sharedtest.logging.LogEventMatcher.withMessageContaining;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class MFAMethodsCreateHandlerTest {
    public static final String TEST_OTP = "123456";

    @RegisterExtension
    private final CaptureLoggingExtension logging =
            new CaptureLoggingExtension(MFAMethodsCreateHandler.class);

    private final Context context = mock(Context.class);
    private static final String TEST_PHONE_NUMBER = "07123123123";
    private static final String TEST_EMAIL = "test@test.com";
    private static final String TEST_SMS_MFA_ID = "35c7940d-be5f-4b31-95b7-0eedc42929b9";
    private static final String TEST_AUTH_APP_ID = "f2ec40f3-9e63-496c-a0a5-a3bdafee868b";
    private static final String TEST_CREDENTIAL = "ZZ11BB22CC33DD44EE55FF66GG77HH88II99JJ00";
    private static final String TEST_CLIENT_ID = "some-client-id";
    private static final String TEST_NON_CLIENT_SESSION_ID = "some-non-client-session-id";
    private static final String TEST_PUBLIC_SUBJECT = new Subject().getValue();
    private static final ConfigurationService configurationService =
            mock(ConfigurationService.class);
    private static final CodeStorageService codeStorageService = mock(CodeStorageService.class);
    private static final MFAMethodsService mfaMethodsService = mock(MFAMethodsService.class);
    private static final DynamoService dynamoService = mock(DynamoService.class);
    private final AwsSqsClient sqsClient = mock(AwsSqsClient.class);
    private static final CloudwatchMetricsService cloudwatchMetricsService =
            mock(CloudwatchMetricsService.class);
    private final AuditService auditService = mock(AuditService.class);
    private final MfaMethodsMigrationService mfaMethodsMigrationService =
            mock(MfaMethodsMigrationService.class);
    private static final byte[] TEST_SALT = SaltHelper.generateNewSalt();
    private static final UserProfile userProfile =
            new UserProfile()
                    .withSubjectID(TEST_PUBLIC_SUBJECT)
                    .withEmail(TEST_EMAIL)
                    .withPhoneNumber(TEST_PHONE_NUMBER);
    private static final String TEST_INTERNAL_SUBJECT =
            ClientSubjectHelper.calculatePairwiseIdentifier(
                    TEST_PUBLIC_SUBJECT, "test.account.gov.uk", TEST_SALT);
    private final Json objectMapper = SerializationService.getInstance();
    private static final AuditContext BASE_AUDIT_CONTEXT =
            AuditContext.emptyAuditContext()
                    .withTxmaAuditEncoded(Optional.of(TXMA_ENCODED_HEADER_VALUE))
                    .withEmail(TEST_EMAIL)
                    .withClientSessionId(SESSION_ID)
                    .withSessionId(TEST_NON_CLIENT_SESSION_ID)
                    .withSubjectId(TEST_INTERNAL_SUBJECT)
                    .withIpAddress(IP_ADDRESS)
                    .withTxmaAuditEncoded(Optional.of(TXMA_ENCODED_HEADER_VALUE))
                    .withPersistentSessionId(PERSISTENT_ID);

    private MFAMethodsCreateHandler handler;

    private APIGatewayProxyRequestEvent generateApiGatewayEvent(
            PriorityIdentifier priorityIdentifier, MfaDetail mfaDetail, String principal) {

        String body =
                mfaDetail instanceof RequestSmsMfaDetail
                        ? format(
                                """
                                 { "mfaMethod": {
                                     "priorityIdentifier": "%s",
                                     "method": {
                                         "mfaMethodType": "SMS",
                                         "phoneNumber": "%s",
                                         "otp": "%s"
                                     }
                                     }
                                 }
                                """,
                                priorityIdentifier,
                                ((RequestSmsMfaDetail) mfaDetail).phoneNumber(),
                                ((RequestSmsMfaDetail) mfaDetail).otp())
                        : format(
                                """
                                 { "mfaMethod": {
                                     "priorityIdentifier": "%s",
                                     "method": {
                                         "mfaMethodType": "AUTH_APP",
                                         "credential": "%s" }
                                     }
                                 }
                                """,
                                priorityIdentifier,
                                ((RequestAuthAppMfaDetail) mfaDetail).credential());

        APIGatewayProxyRequestEvent.ProxyRequestContext proxyRequestContext =
                new APIGatewayProxyRequestEvent.ProxyRequestContext();
        Map<String, Object> authorizerParams = new HashMap<>();
        authorizerParams.put("principalId", principal);
        authorizerParams.put("clientId", TEST_CLIENT_ID);
        proxyRequestContext.setAuthorizer(authorizerParams);
        proxyRequestContext.setIdentity(identityWithSourceIp(IP_ADDRESS));

        Map<String, String> headers = new HashMap<>(VALID_HEADERS);
        headers.put(SESSION_ID_HEADER, TEST_NON_CLIENT_SESSION_ID);

        return new APIGatewayProxyRequestEvent()
                .withPathParameters(Map.of("publicSubjectId", TEST_PUBLIC_SUBJECT))
                .withBody(body)
                .withRequestContext(proxyRequestContext)
                .withHeaders(headers);
    }

    @BeforeEach
    void setUp() {
        reset(mfaMethodsService, cloudwatchMetricsService);
        when(configurationService.isMfaMethodManagementApiEnabled()).thenReturn(true);
        when(configurationService.isAccountManagementInternationalSmsEnabled()).thenReturn(true);
        when(configurationService.getEnvironment()).thenReturn("test");
        handler =
                new MFAMethodsCreateHandler(
                        configurationService,
                        mfaMethodsService,
                        dynamoService,
                        codeStorageService,
                        auditService,
                        sqsClient,
                        cloudwatchMetricsService,
                        mfaMethodsMigrationService);
        when(configurationService.getAwsRegion()).thenReturn("eu-west-2");
        when(configurationService.getInternalSectorUri()).thenReturn("https://test.account.gov.uk");
        when(dynamoService.getOrGenerateSalt(userProfile)).thenReturn(TEST_SALT);
        when(dynamoService.getOptionalUserProfileFromPublicSubject(TEST_PUBLIC_SUBJECT))
                .thenReturn(Optional.of(userProfile));
        when(mfaMethodsService.migrateMfaCredentialsForUser(any()))
                .thenReturn(Result.success(false));
    }

    @AfterEach
    void resetMocks() {
        reset(configurationService);
        reset(dynamoService);
        reset(mfaMethodsService);
        reset(codeStorageService);
    }

    @Nested
    class SuccessfulRequest {

        @Test
        void shouldReturn200AndCreateMfaSmsMfaMethod() throws Json.JsonException {
            var backupMfa =
                    MFAMethod.smsMfaMethod(
                            true,
                            true,
                            TEST_PHONE_NUMBER,
                            PriorityIdentifier.BACKUP,
                            TEST_SMS_MFA_ID);
            when(mfaMethodsService.addBackupMfa(any(), any()))
                    .thenReturn(Result.success(backupMfa));
            when(codeStorageService.isValidOtpCode(any(), any(), any())).thenReturn(true);

            var event =
                    generateApiGatewayEvent(
                            PriorityIdentifier.BACKUP,
                            new RequestSmsMfaDetail(TEST_PHONE_NUMBER, TEST_OTP),
                            TEST_INTERNAL_SUBJECT);

            var result = handler.handleRequest(event, context);

            ArgumentCaptor<MfaMethodCreateRequest.MfaMethod> mfaMethodCaptor =
                    ArgumentCaptor.forClass(MfaMethodCreateRequest.MfaMethod.class);

            verify(mfaMethodsService).addBackupMfa(eq(TEST_EMAIL), mfaMethodCaptor.capture());
            var capturedRequest = mfaMethodCaptor.getValue();

            assertEquals(
                    new RequestSmsMfaDetail(TEST_PHONE_NUMBER, TEST_OTP), capturedRequest.method());
            assertEquals(PriorityIdentifier.BACKUP, capturedRequest.priorityIdentifier());

            verify(sqsClient)
                    .send(
                            objectMapper.writeValueAsString(
                                    new NotifyRequest(
                                            TEST_EMAIL,
                                            NotificationType.BACKUP_METHOD_ADDED,
                                            LocaleHelper.SupportedLanguage.EN)));

            assertThat(result, hasStatus(200));
            var expectedResponse =
                    format(
                            """
                                    {
                                      "mfaIdentifier": "%s",
                                      "priorityIdentifier": "BACKUP",
                                      "methodVerified": true,
                                      "method": {
                                        "mfaMethodType": "SMS",
                                        "phoneNumber": "%s"
                                      }
                                    }
                                    """,
                            TEST_SMS_MFA_ID, TEST_PHONE_NUMBER);
            var expectedResponseParsedToString =
                    JsonParser.parseString(expectedResponse).getAsJsonObject().toString();
            assertEquals(expectedResponseParsedToString, result.getBody());

            verify(auditService)
                    .submitAuditEvent(
                            AUTH_CODE_VERIFIED,
                            BASE_AUDIT_CONTEXT.withPhoneNumber(TEST_PHONE_NUMBER),
                            AUDIT_EVENT_COMPONENT_ID_HOME,
                            AuditHelper.ACCOUNT_MANAGEMENT_JOURNEY_TYPE_PAIR,
                            pair("mfa-type", SMS.name()),
                            pair("mfa-method", BACKUP.name().toLowerCase()),
                            pair("phone_number_country_code", "44"),
                            pair("MFACodeEntered", TEST_OTP),
                            pair("notification-type", MFA_SMS.name()),
                            pair("account-recovery", "false"));

            verify(auditService)
                    .submitAuditEvent(
                            AUTH_MFA_METHOD_ADD_COMPLETED,
                            BASE_AUDIT_CONTEXT.withPhoneNumber(TEST_PHONE_NUMBER),
                            AUDIT_EVENT_COMPONENT_ID_HOME,
                            AuditHelper.ACCOUNT_MANAGEMENT_JOURNEY_TYPE_PAIR,
                            pair("mfa-type", SMS.name()),
                            pair("mfa-method", BACKUP.name().toLowerCase()),
                            pair("phone_number_country_code", "44"));

            verify(auditService)
                    .submitAuditEvent(
                            AUTH_UPDATE_PHONE_NUMBER,
                            BASE_AUDIT_CONTEXT.withPhoneNumber(TEST_PHONE_NUMBER),
                            AUDIT_EVENT_COMPONENT_ID_HOME,
                            AuditHelper.ACCOUNT_MANAGEMENT_JOURNEY_TYPE_PAIR,
                            pair("mfa-type", SMS.name()),
                            pair("mfa-method", BACKUP.name().toLowerCase()),
                            pair("phone_number_country_code", "44"));
        }

        @Test
        void shouldReturn200AndCreateAuthAppMfa() throws Json.JsonException {
            var authAppBackup =
                    MFAMethod.authAppMfaMethod(
                            TEST_CREDENTIAL,
                            true,
                            true,
                            PriorityIdentifier.BACKUP,
                            TEST_AUTH_APP_ID);
            when(mfaMethodsService.addBackupMfa(any(), any()))
                    .thenReturn(Result.success(authAppBackup));
            var defaultMfa =
                    MFAMethod.authAppMfaMethod(
                            "cred", true, true, PriorityIdentifier.DEFAULT, TEST_AUTH_APP_ID);

            when(mfaMethodsService.getMfaMethods(TEST_EMAIL))
                    .thenReturn(Result.success(List.of(defaultMfa)));

            var event =
                    generateApiGatewayEvent(
                            PriorityIdentifier.BACKUP,
                            new RequestAuthAppMfaDetail(TEST_CREDENTIAL),
                            TEST_INTERNAL_SUBJECT);

            var result = handler.handleRequest(event, context);

            ArgumentCaptor<MfaMethodCreateRequest.MfaMethod> mfaMethodCaptor =
                    ArgumentCaptor.forClass(MfaMethodCreateRequest.MfaMethod.class);

            verify(mfaMethodsService).addBackupMfa(eq(TEST_EMAIL), mfaMethodCaptor.capture());
            var capturedRequest = mfaMethodCaptor.getValue();

            assertEquals(new RequestAuthAppMfaDetail(TEST_CREDENTIAL), capturedRequest.method());
            assertEquals(PriorityIdentifier.BACKUP, capturedRequest.priorityIdentifier());

            assertThat(result, hasStatus(200));
            var expectedResponse =
                    format(
                            """
                                    {
                                      "mfaIdentifier": "%s",
                                      "priorityIdentifier": "BACKUP",
                                      "methodVerified": true,
                                      "method": {
                                        "mfaMethodType": "AUTH_APP",
                                        "credential": "%s"
                                      }
                                    }
                                    """,
                            TEST_AUTH_APP_ID, TEST_CREDENTIAL);
            var expectedResponseParsedToString =
                    JsonParser.parseString(expectedResponse).getAsJsonObject().toString();
            assertEquals(expectedResponseParsedToString, result.getBody());

            verify(sqsClient)
                    .send(
                            objectMapper.writeValueAsString(
                                    new NotifyRequest(
                                            TEST_EMAIL,
                                            NotificationType.BACKUP_METHOD_ADDED,
                                            LocaleHelper.SupportedLanguage.EN)));

            verify(auditService, never())
                    .submitAuditEvent(eq(AUTH_UPDATE_PHONE_NUMBER), any(), any());

            verify(auditService)
                    .submitAuditEvent(
                            AUTH_CODE_VERIFIED,
                            BASE_AUDIT_CONTEXT.withPhoneNumber(null),
                            AUDIT_EVENT_COMPONENT_ID_HOME,
                            AuditHelper.ACCOUNT_MANAGEMENT_JOURNEY_TYPE_PAIR,
                            pair("mfa-type", AUTH_APP.name()),
                            pair("mfa-method", BACKUP.name().toLowerCase()),
                            pair("account-recovery", "false"));

            verify(auditService)
                    .submitAuditEvent(
                            AUTH_MFA_METHOD_ADD_COMPLETED,
                            BASE_AUDIT_CONTEXT.withPhoneNumber(null),
                            AUDIT_EVENT_COMPONENT_ID_HOME,
                            AuditHelper.ACCOUNT_MANAGEMENT_JOURNEY_TYPE_PAIR,
                            pair("mfa-type", AUTH_APP.name()),
                            pair("mfa-method", BACKUP.name().toLowerCase()));
        }

        @Test
        void shouldIncrementTheCorrectMfaMethodCounter() {
            var authAppBackup =
                    MFAMethod.authAppMfaMethod(
                            TEST_CREDENTIAL,
                            true,
                            true,
                            PriorityIdentifier.BACKUP,
                            TEST_AUTH_APP_ID);
            when(mfaMethodsService.addBackupMfa(any(), any()))
                    .thenReturn(Result.success(authAppBackup));
            when(configurationService.getEnvironment()).thenReturn("test");

            var event =
                    generateApiGatewayEvent(
                            PriorityIdentifier.BACKUP,
                            new RequestAuthAppMfaDetail(TEST_CREDENTIAL),
                            TEST_INTERNAL_SUBJECT);

            handler.handleRequest(event, context);

            verify(cloudwatchMetricsService)
                    .incrementMfaMethodCounter(
                            "test",
                            "CreateMfaMethod",
                            "SUCCESS",
                            ACCOUNT_MANAGEMENT,
                            "AUTH_APP",
                            PriorityIdentifier.BACKUP);
        }

        @Test
        void shouldRaiseAuthCodeVerifiedAuditEvent() {
            var backupMfa =
                    MFAMethod.smsMfaMethod(
                            true,
                            true,
                            TEST_PHONE_NUMBER,
                            PriorityIdentifier.BACKUP,
                            TEST_SMS_MFA_ID);
            when(mfaMethodsService.addBackupMfa(any(), any()))
                    .thenReturn(Result.success(backupMfa));
            when(codeStorageService.isValidOtpCode(any(), any(), any())).thenReturn(true);

            var event =
                    generateApiGatewayEvent(
                            PriorityIdentifier.BACKUP,
                            new RequestSmsMfaDetail(TEST_PHONE_NUMBER, TEST_OTP),
                            TEST_INTERNAL_SUBJECT);

            handler.handleRequest(event, context);

            verify(auditService)
                    .submitAuditEvent(
                            AUTH_CODE_VERIFIED,
                            BASE_AUDIT_CONTEXT.withPhoneNumber(TEST_PHONE_NUMBER),
                            AUDIT_EVENT_COMPONENT_ID_HOME,
                            AuditHelper.ACCOUNT_MANAGEMENT_JOURNEY_TYPE_PAIR,
                            pair("mfa-type", SMS.name()),
                            pair("mfa-method", BACKUP.name().toLowerCase()),
                            pair("phone_number_country_code", "44"),
                            pair("MFACodeEntered", TEST_OTP),
                            pair("notification-type", MFA_SMS.name()),
                            pair("account-recovery", "false"));
        }
    }

    @Nested
    class FailedRequest {

        private static Stream<Arguments> migrationFailureReasonsToExpectedResponses() {
            return Stream.of(
                    Arguments.of(ErrorResponse.USER_NOT_FOUND, 404),
                    Arguments.of(ErrorResponse.MFA_METHODS_RETRIEVAL_ERROR, 500));
        }

        @ParameterizedTest
        @MethodSource("migrationFailureReasonsToExpectedResponses")
        void shouldReturnRelevantStatusCodeWhenMigrationFailed(
                ErrorResponse expectedError, int expectedStatusCode) {
            when(dynamoService.getOptionalUserProfileFromPublicSubject(TEST_PUBLIC_SUBJECT))
                    .thenReturn(Optional.of(userProfile));
            when(codeStorageService.isValidOtpCode(any(), any(), any())).thenReturn(true);
            var expectedResponseBody =
                    format(
                            "{\"code\":%d,\"message\":\"%s\"}",
                            expectedError.getCode(), expectedError.getMessage());
            var expectedGateway =
                    new APIGatewayProxyResponseEvent()
                            .withStatusCode(expectedStatusCode)
                            .withBody(expectedResponseBody);
            when(mfaMethodsMigrationService.migrateMfaCredentialsForUserIfRequired(
                            any(), any(), any(), any()))
                    .thenReturn(Optional.of(expectedGateway));

            var event =
                    generateApiGatewayEvent(
                            PriorityIdentifier.BACKUP,
                            new RequestSmsMfaDetail(TEST_PHONE_NUMBER, TEST_OTP),
                            TEST_INTERNAL_SUBJECT);

            var result = handler.handleRequest(event, context);

            assertThat(result, hasStatus(expectedStatusCode));
            assertTrue(result.getBody().contains(String.valueOf(expectedError.getCode())));
            assertTrue(result.getBody().contains(expectedError.getMessage()));
            verifyNoInteractions(sqsClient);
        }

        @Test
        void shouldReturn400IfRequestIsMadeInEnvWhereApiNotEnabled() {
            when(configurationService.isMfaMethodManagementApiEnabled()).thenReturn(false);

            var event =
                    generateApiGatewayEvent(
                            PriorityIdentifier.BACKUP,
                            new RequestAuthAppMfaDetail(TEST_CREDENTIAL),
                            TEST_INTERNAL_SUBJECT);

            var result = handler.handleRequest(event, context);

            assertThat(result, hasStatus(400));
            verifyNoInteractions(sqsClient);
            verifyNoInteractions(auditService);
        }

        @Test
        void shouldReturn400WhenInternationalNumberAndFeatureFlagDisabled() {
            when(configurationService.isAccountManagementInternationalSmsEnabled())
                    .thenReturn(false);
            when(mfaMethodsService.getMfaMethods(TEST_EMAIL)).thenReturn(Result.success(List.of()));

            var event =
                    generateApiGatewayEvent(
                            PriorityIdentifier.BACKUP,
                            new RequestSmsMfaDetail(INTERNATIONAL_MOBILE_NUMBER, TEST_OTP),
                            TEST_INTERNAL_SUBJECT);

            var result = handler.handleRequest(event, context);

            assertThat(result, hasStatus(400));
            assertThat(result, hasJsonBody(ErrorResponse.INTERNATIONAL_PHONE_NUMBER_NOT_SUPPORTED));
            verifyNoInteractions(sqsClient);
            verifyNoInteractions(auditService);
        }

        @Test
        void shouldReturn400WhenPathParameterIsEmpty() {
            var event = new APIGatewayProxyRequestEvent();
            event.setPathParameters(Map.of());

            var result = handler.handleRequest(event, context);

            assertThat(result, hasStatus(400));
            assertThat(result, hasJsonBody(ErrorResponse.REQUEST_MISSING_PARAMS));
            assertThat(
                    logging.events(),
                    hasItem(
                            withMessageContaining(
                                    "Subject missing from request prevents request being handled.")));
            verifyNoInteractions(sqsClient);
            verifyNoInteractions(auditService);
        }

        @Test
        void shouldReturn404WhenUserProfileNotFoundForPublicSubject() {
            when(dynamoService.getOptionalUserProfileFromPublicSubject(TEST_PUBLIC_SUBJECT))
                    .thenReturn(Optional.empty());

            var event =
                    generateApiGatewayEvent(
                            PriorityIdentifier.BACKUP,
                            new RequestAuthAppMfaDetail(TEST_CREDENTIAL),
                            TEST_INTERNAL_SUBJECT);

            var result = handler.handleRequest(event, context);

            assertThat(result, hasStatus(404));
            assertThat(result, hasJsonBody(ErrorResponse.USER_NOT_FOUND));
            verifyNoInteractions(sqsClient);
            verifyNoInteractions(auditService);
        }

        @Test
        void shouldReturn400WhenJsonIsInvalid() {
            var event =
                    generateApiGatewayEvent(
                            PriorityIdentifier.BACKUP,
                            new RequestSmsMfaDetail(TEST_PHONE_NUMBER, TEST_OTP),
                            TEST_INTERNAL_SUBJECT);
            event.setBody("Invalid JSON");

            var result = handler.handleRequest(event, context);

            assertThat(result, hasStatus(400));
            assertThat(result, hasJsonBody(ErrorResponse.REQUEST_MISSING_PARAMS));
            verifyNoInteractions(auditService);
        }

        @Test
        void shouldReturn400WhenRequestToCreateNewDefault() {
            var event =
                    generateApiGatewayEvent(
                            DEFAULT,
                            new RequestSmsMfaDetail(TEST_PHONE_NUMBER, TEST_OTP),
                            TEST_INTERNAL_SUBJECT);

            var result = handler.handleRequest(event, context);

            assertThat(result, hasStatus(400));
            assertThat(result, hasJsonBody(ErrorResponse.DEFAULT_MFA_ALREADY_EXISTS));
            verifyNoInteractions(auditService);
        }

        @Test
        void shouldReturn400WhenMfaMethodServiceReturnsBackupAndDefaultExistError() {
            var event =
                    generateApiGatewayEvent(
                            PriorityIdentifier.BACKUP,
                            new RequestSmsMfaDetail(TEST_PHONE_NUMBER, TEST_OTP),
                            TEST_INTERNAL_SUBJECT);
            when(codeStorageService.isValidOtpCode(
                            TEST_EMAIL, TEST_OTP, NotificationType.VERIFY_PHONE_NUMBER))
                    .thenReturn(true);
            when(dynamoService.getOptionalUserProfileFromPublicSubject(TEST_PUBLIC_SUBJECT))
                    .thenReturn(Optional.of(userProfile));
            when(mfaMethodsService.addBackupMfa(any(), any()))
                    .thenReturn(
                            Result.failure(
                                    MfaCreateFailureReason
                                            .BACKUP_AND_DEFAULT_METHOD_ALREADY_EXIST));

            var defaultMfa =
                    MFAMethod.authAppMfaMethod(
                            "cred", true, true, PriorityIdentifier.DEFAULT, TEST_AUTH_APP_ID);

            when(mfaMethodsService.getMfaMethods(TEST_EMAIL))
                    .thenReturn(Result.success(List.of(defaultMfa)));

            var result = handler.handleRequest(event, context);

            assertThat(result, hasStatus(400));
            assertThat(result, hasJsonBody(ErrorResponse.MFA_METHOD_COUNT_LIMIT_REACHED));

            verify(auditService)
                    .submitAuditEvent(
                            AUTH_MFA_METHOD_ADD_FAILED,
                            BASE_AUDIT_CONTEXT.withPhoneNumber(null),
                            AUDIT_EVENT_COMPONENT_ID_HOME,
                            AuditHelper.ACCOUNT_MANAGEMENT_JOURNEY_TYPE_PAIR,
                            pair("mfa-type", AUTH_APP.toString()),
                            pair("mfa-method", DEFAULT.name().toLowerCase()));
        }

        @Test
        void shouldReturn400WhenMfaMethodServiceReturnsInvalidPhoneNumberError() {
            var event =
                    generateApiGatewayEvent(
                            PriorityIdentifier.BACKUP,
                            new RequestSmsMfaDetail("not a real phone number", TEST_OTP),
                            TEST_INTERNAL_SUBJECT);
            when(codeStorageService.isValidOtpCode(
                            TEST_EMAIL, TEST_OTP, NotificationType.VERIFY_PHONE_NUMBER))
                    .thenReturn(true);
            when(dynamoService.getOptionalUserProfileFromPublicSubject(TEST_PUBLIC_SUBJECT))
                    .thenReturn(Optional.of(userProfile));
            when(mfaMethodsService.addBackupMfa(any(), any()))
                    .thenReturn(Result.failure(MfaCreateFailureReason.INVALID_PHONE_NUMBER));
            var defaultMfa =
                    MFAMethod.authAppMfaMethod(
                            "cred", true, true, PriorityIdentifier.DEFAULT, TEST_AUTH_APP_ID);

            when(mfaMethodsService.getMfaMethods(TEST_EMAIL))
                    .thenReturn(Result.success(List.of(defaultMfa)));

            var result = handler.handleRequest(event, context);

            assertThat(result, hasStatus(400));
            assertThat(result, hasJsonBody(ErrorResponse.INVALID_PHONE_NUMBER));

            // Query: should this instead be reflecting the method that has failed to add? Ie sms

            verify(auditService)
                    .submitAuditEvent(
                            AUTH_MFA_METHOD_ADD_FAILED,
                            BASE_AUDIT_CONTEXT.withPhoneNumber(null),
                            AUDIT_EVENT_COMPONENT_ID_HOME,
                            AuditHelper.ACCOUNT_MANAGEMENT_JOURNEY_TYPE_PAIR,
                            pair("mfa-type", AUTH_APP.toString()),
                            pair("mfa-method", DEFAULT.name().toLowerCase()));
        }

        @Test
        void shouldReturn400WhenPhoneNumberValidationFails() {
            var invalidPhoneNumber = "invalid-phone-number";
            var event =
                    generateApiGatewayEvent(
                            PriorityIdentifier.BACKUP,
                            new RequestSmsMfaDetail(invalidPhoneNumber, TEST_OTP),
                            TEST_INTERNAL_SUBJECT);
            when(dynamoService.getOptionalUserProfileFromPublicSubject(TEST_PUBLIC_SUBJECT))
                    .thenReturn(Optional.of(userProfile));

            var defaultMfa =
                    MFAMethod.authAppMfaMethod(
                            "cred", true, true, PriorityIdentifier.DEFAULT, TEST_AUTH_APP_ID);

            when(mfaMethodsService.getMfaMethods(TEST_EMAIL))
                    .thenReturn(Result.success(List.of(defaultMfa)));

            var result = handler.handleRequest(event, context);

            assertThat(result, hasStatus(400));
            assertThat(result, hasJsonBody(ErrorResponse.INVALID_PHONE_NUMBER));

            verify(auditService)
                    .submitAuditEvent(
                            AUTH_MFA_METHOD_ADD_FAILED,
                            BASE_AUDIT_CONTEXT.withPhoneNumber(null),
                            AUDIT_EVENT_COMPONENT_ID_HOME,
                            AuditHelper.ACCOUNT_MANAGEMENT_JOURNEY_TYPE_PAIR,
                            pair("mfa-type", AUTH_APP.toString()),
                            pair("mfa-method", DEFAULT.name().toLowerCase()));

            // Verify that getMfaMethods was called but addBackupMfa was not
            // TODO: fix twice calling of getMfaMethods
            verify(mfaMethodsService, times(2)).getMfaMethods(TEST_EMAIL);
            verify(mfaMethodsService, org.mockito.Mockito.never()).addBackupMfa(any(), any());
        }

        @Test
        void shouldReturn400WhenOTPIsInvalid() {
            var event =
                    generateApiGatewayEvent(
                            PriorityIdentifier.BACKUP,
                            new RequestSmsMfaDetail(TEST_PHONE_NUMBER, TEST_OTP),
                            TEST_INTERNAL_SUBJECT);
            when(codeStorageService.isValidOtpCode(
                            TEST_EMAIL, TEST_OTP, NotificationType.VERIFY_PHONE_NUMBER))
                    .thenReturn(false);
            when(dynamoService.getOptionalUserProfileFromPublicSubject(TEST_PUBLIC_SUBJECT))
                    .thenReturn(Optional.of(userProfile));
            when(mfaMethodsService.addBackupMfa(any(), any()))
                    .thenReturn(
                            Result.failure(
                                    MfaCreateFailureReason
                                            .BACKUP_AND_DEFAULT_METHOD_ALREADY_EXIST));

            var result = handler.handleRequest(event, context);

            assertThat(result, hasStatus(400));
            assertThat(result, hasJsonBody(ErrorResponse.INVALID_OTP));

            verify(auditService)
                    .submitAuditEvent(
                            AUTH_INVALID_CODE_SENT,
                            BASE_AUDIT_CONTEXT.withPhoneNumber(TEST_PHONE_NUMBER),
                            AUDIT_EVENT_COMPONENT_ID_HOME,
                            AuditHelper.ACCOUNT_MANAGEMENT_JOURNEY_TYPE_PAIR,
                            pair("mfa-type", SMS.toString()),
                            pair("mfa-method", BACKUP.name().toLowerCase()),
                            pair("phone_number_country_code", "44"));

            verifyNoInteractions(sqsClient);
        }

        @Test
        void shouldReturn400WhenMfaMethodServiceReturnsSmsMfaAlreadyExistsError() {
            var event =
                    generateApiGatewayEvent(
                            PriorityIdentifier.BACKUP,
                            new RequestSmsMfaDetail(TEST_PHONE_NUMBER, TEST_OTP),
                            TEST_INTERNAL_SUBJECT);
            when(dynamoService.getOptionalUserProfileFromPublicSubject(TEST_PUBLIC_SUBJECT))
                    .thenReturn(Optional.of(userProfile));
            when(codeStorageService.isValidOtpCode(any(), any(), any())).thenReturn(true);
            when(mfaMethodsService.addBackupMfa(any(), any()))
                    .thenReturn(Result.failure(MfaCreateFailureReason.PHONE_NUMBER_ALREADY_EXISTS));
            var defaultMfa =
                    MFAMethod.authAppMfaMethod(
                            "cred", true, true, PriorityIdentifier.DEFAULT, TEST_AUTH_APP_ID);

            when(mfaMethodsService.getMfaMethods(TEST_EMAIL))
                    .thenReturn(Result.success(List.of(defaultMfa)));

            var result = handler.handleRequest(event, context);

            assertThat(result, hasStatus(400));
            assertThat(result, hasJsonBody(ErrorResponse.SMS_MFA_WITH_NUMBER_EXISTS));

            verify(auditService)
                    .submitAuditEvent(
                            AUTH_MFA_METHOD_ADD_FAILED,
                            BASE_AUDIT_CONTEXT.withPhoneNumber(null),
                            AUDIT_EVENT_COMPONENT_ID_HOME,
                            AuditHelper.ACCOUNT_MANAGEMENT_JOURNEY_TYPE_PAIR,
                            pair("mfa-type", AUTH_APP.toString()),
                            pair("mfa-method", DEFAULT.name().toLowerCase()));
        }

        @Test
        void shouldReturn400WhenMfaMethodServiceReturnsAuthAppAlreadyExistsError() {
            var event =
                    generateApiGatewayEvent(
                            PriorityIdentifier.BACKUP,
                            new RequestAuthAppMfaDetail(TEST_CREDENTIAL),
                            TEST_INTERNAL_SUBJECT);
            when(dynamoService.getOptionalUserProfileFromPublicSubject(TEST_PUBLIC_SUBJECT))
                    .thenReturn(Optional.of(userProfile));
            when(mfaMethodsService.addBackupMfa(any(), any()))
                    .thenReturn(Result.failure(MfaCreateFailureReason.AUTH_APP_EXISTS));
            var defaultMfa =
                    MFAMethod.authAppMfaMethod(
                            "cred", true, true, PriorityIdentifier.DEFAULT, TEST_AUTH_APP_ID);

            when(mfaMethodsService.getMfaMethods(TEST_EMAIL))
                    .thenReturn(Result.success(List.of(defaultMfa)));

            var result = handler.handleRequest(event, context);

            assertThat(result, hasStatus(400));
            assertThat(result, hasJsonBody(ErrorResponse.AUTH_APP_EXISTS));

            verify(auditService)
                    .submitAuditEvent(
                            AUTH_MFA_METHOD_ADD_FAILED,
                            BASE_AUDIT_CONTEXT.withPhoneNumber(null),
                            AUDIT_EVENT_COMPONENT_ID_HOME,
                            AuditHelper.ACCOUNT_MANAGEMENT_JOURNEY_TYPE_PAIR,
                            pair("mfa-type", AUTH_APP.toString()),
                            pair("mfa-method", DEFAULT.name().toLowerCase()));
        }

        @Test
        void shouldReturn500WhenReturnedMfaMethodDoesNotConvertToMfaResponse() {
            var mfaMethodWithInvalidMfaType =
                    new MFAMethod(
                            "invalid mfa type", TEST_CREDENTIAL, true, true, "updated-timestamp");
            var event =
                    generateApiGatewayEvent(
                            PriorityIdentifier.BACKUP,
                            new RequestAuthAppMfaDetail(TEST_CREDENTIAL),
                            TEST_INTERNAL_SUBJECT);
            when(dynamoService.getOptionalUserProfileFromPublicSubject(TEST_PUBLIC_SUBJECT))
                    .thenReturn(Optional.of(userProfile));
            when(mfaMethodsService.addBackupMfa(any(), any()))
                    .thenReturn(Result.success(mfaMethodWithInvalidMfaType));
            var defaultMfa =
                    MFAMethod.smsMfaMethod(
                            true,
                            true,
                            TEST_PHONE_NUMBER,
                            PriorityIdentifier.DEFAULT,
                            TEST_SMS_MFA_ID);

            when(mfaMethodsService.getMfaMethods(TEST_EMAIL))
                    .thenReturn(Result.success(List.of(defaultMfa)));

            var result = handler.handleRequest(event, context);

            assertThat(result, hasStatus(500));
            assertThat(result, hasJsonBody(ErrorResponse.UNEXPECTED_ACCT_MGMT_ERROR));
            verifyNoInteractions(sqsClient);

            verify(auditService)
                    .submitAuditEvent(
                            AUTH_MFA_METHOD_ADD_FAILED,
                            BASE_AUDIT_CONTEXT.withPhoneNumber(TEST_PHONE_NUMBER),
                            AUDIT_EVENT_COMPONENT_ID_HOME,
                            AuditHelper.ACCOUNT_MANAGEMENT_JOURNEY_TYPE_PAIR,
                            pair("mfa-type", SMS.toString()),
                            pair("mfa-method", DEFAULT.name().toLowerCase()));
        }

        @Test
        void shouldReturn401WhenPrincipalIsInvalid() {
            var event =
                    generateApiGatewayEvent(
                            PriorityIdentifier.BACKUP,
                            new RequestAuthAppMfaDetail(TEST_CREDENTIAL),
                            "invalid");

            var result = handler.handleRequest(event, context);

            assertThat(result, hasStatus(401));
            assertThat(result, hasJsonBody(ErrorResponse.INVALID_PRINCIPAL));
            verifyNoInteractions(auditService);
        }
    }
}
