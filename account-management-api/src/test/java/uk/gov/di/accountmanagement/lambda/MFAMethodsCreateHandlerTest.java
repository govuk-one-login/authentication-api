package uk.gov.di.accountmanagement.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.google.gson.JsonParser;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;
import uk.gov.di.accountmanagement.domain.AccountManagementAuditableEvent;
import uk.gov.di.accountmanagement.entity.NotificationType;
import uk.gov.di.accountmanagement.entity.NotifyRequest;
import uk.gov.di.accountmanagement.helpers.AuditHelper;
import uk.gov.di.accountmanagement.services.AwsSqsClient;
import uk.gov.di.accountmanagement.services.CodeStorageService;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.audit.TxmaAuditUser;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.PriorityIdentifier;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethod;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.entity.mfa.MfaDetail;
import uk.gov.di.authentication.shared.entity.mfa.request.MfaMethodCreateRequest;
import uk.gov.di.authentication.shared.entity.mfa.request.RequestAuthAppMfaDetail;
import uk.gov.di.authentication.shared.entity.mfa.request.RequestSmsMfaDetail;
import uk.gov.di.authentication.shared.helpers.ClientSessionIdHelper;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.helpers.LocaleHelper;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.helpers.SaltHelper;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuditService.MetadataPair;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.SerializationService;
import uk.gov.di.authentication.shared.services.mfa.MFAMethodsService;
import uk.gov.di.authentication.shared.services.mfa.MfaCreateFailureReason;
import uk.gov.di.authentication.shared.services.mfa.MfaMigrationFailureReason;
import uk.gov.di.authentication.sharedtest.logging.CaptureLoggingExtension;

import java.util.HashMap;
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
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.di.accountmanagement.helpers.CommonTestVariables.PERSISTENT_ID;
import static uk.gov.di.accountmanagement.helpers.CommonTestVariables.SESSION_ID;
import static uk.gov.di.accountmanagement.helpers.CommonTestVariables.TXMA_ENCODED_HEADER_VALUE;
import static uk.gov.di.accountmanagement.helpers.CommonTestVariables.VALID_HEADERS;
import static uk.gov.di.authentication.shared.domain.RequestHeaders.SESSION_ID_HEADER;
import static uk.gov.di.authentication.shared.services.AuditService.MetadataPair.pair;
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
    private static final String TEST_PUBLIC_SUBJECT = new Subject().getValue();
    private static final ConfigurationService configurationService =
            mock(ConfigurationService.class);
    private static final CodeStorageService codeStorageService = mock(CodeStorageService.class);
    private static final MFAMethodsService mfaMethodsService = mock(MFAMethodsService.class);
    private static final DynamoService dynamoService = mock(DynamoService.class);
    private final AwsSqsClient sqsClient = mock(AwsSqsClient.class);
    private final AuditService auditService = mock(AuditService.class);
    private static final byte[] TEST_SALT = SaltHelper.generateNewSalt();
    private static final UserProfile userProfile =
            new UserProfile().withSubjectID(TEST_PUBLIC_SUBJECT).withEmail(TEST_EMAIL);
    private static final String TEST_INTERNAL_SUBJECT =
            ClientSubjectHelper.calculatePairwiseIdentifier(
                    TEST_PUBLIC_SUBJECT, "test.account.gov.uk", TEST_SALT);
    private final Json objectMapper = SerializationService.getInstance();

    private MFAMethodsCreateHandler handler;

    @BeforeEach
    void setUp() {
        reset(mfaMethodsService);
        when(configurationService.isMfaMethodManagementApiEnabled()).thenReturn(true);
        handler =
                new MFAMethodsCreateHandler(
                        configurationService,
                        mfaMethodsService,
                        dynamoService,
                        codeStorageService,
                        sqsClient,
                        auditService);
        when(configurationService.getAwsRegion()).thenReturn("eu-west-2");
        when(configurationService.getInternalSectorUri()).thenReturn("https://test.account.gov.uk");
        when(dynamoService.getOrGenerateSalt(userProfile)).thenReturn(TEST_SALT);
        when(dynamoService.getOptionalUserProfileFromPublicSubject(TEST_PUBLIC_SUBJECT))
                .thenReturn(Optional.of(userProfile));
        reset(mfaMethodsService);
        when(mfaMethodsService.migrateMfaCredentialsForUser(any())).thenReturn(Optional.empty());
    }

    private static Stream<Arguments> migrationFailureReasonsToExpectedResponses() {
        return Stream.of(
                Arguments.of(
                        MfaMigrationFailureReason.NO_USER_FOUND_FOR_EMAIL,
                        ErrorResponse.ERROR_1056,
                        404),
                Arguments.of(
                        MfaMigrationFailureReason.UNEXPECTED_ERROR_RETRIEVING_METHODS,
                        ErrorResponse.ERROR_1064,
                        500));
    }

    @ParameterizedTest
    @MethodSource("migrationFailureReasonsToExpectedResponses")
    void shouldReturnRelevantStatusCodeWhenMigrationFailed(
            MfaMigrationFailureReason reason, ErrorResponse expectedError, int expectedStatusCode) {
        when(dynamoService.getOptionalUserProfileFromPublicSubject(TEST_PUBLIC_SUBJECT))
                .thenReturn(Optional.of(userProfile));
        when(mfaMethodsService.migrateMfaCredentialsForUser(any())).thenReturn(Optional.of(reason));

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
    void shouldReturn200AndCreateMfaSmsMfaMethod() throws Json.JsonException {
        var backupMfa =
                MFAMethod.smsMfaMethod(
                        true, true, TEST_PHONE_NUMBER, PriorityIdentifier.BACKUP, TEST_SMS_MFA_ID);
        when(mfaMethodsService.addBackupMfa(any(), any())).thenReturn(Result.success(backupMfa));

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

        // Verify audit event is emitted with all required fields
        ArgumentCaptor<AuditContext> auditContextCaptor =
                ArgumentCaptor.forClass(AuditContext.class);
        verify(auditService)
                .submitAuditEvent(
                        eq(AccountManagementAuditableEvent.AUTH_MFA_METHOD_MIGRATION_ATTEMPTED),
                        auditContextCaptor.capture());

        AuditContext capturedContext = auditContextCaptor.getValue();
        assertEquals(TEST_CLIENT_ID, capturedContext.clientId());
        assertEquals(TEST_EMAIL, capturedContext.email());
        assertEquals(TEST_PUBLIC_SUBJECT, capturedContext.subjectId());
        assertEquals(userProfile.getPhoneNumber(), capturedContext.phoneNumber());
        assertEquals("123.123.123.123", capturedContext.ipAddress());

        // Verify client session ID and persistent session ID from headers
        assertEquals(SESSION_ID, capturedContext.clientSessionId());
        assertEquals(PERSISTENT_ID, capturedContext.persistentSessionId());

        // Verify the User section of the audit event would be correctly populated
        TxmaAuditUser expectedUser =
                TxmaAuditUser.user()
                        .withUserId(TEST_PUBLIC_SUBJECT)
                        .withEmail(TEST_EMAIL)
                        .withPhone(userProfile.getPhoneNumber())
                        .withIpAddress("123.123.123.123")
                        .withSessionId(null) // Session ID is not set in this context
                        .withPersistentSessionId(PERSISTENT_ID)
                        .withGovukSigninJourneyId(SESSION_ID);

        // Verify the audit context matches the expected user data
        assertEquals(expectedUser.getPhone(), capturedContext.phoneNumber());
        assertEquals("123.123.123.123", capturedContext.ipAddress());
        assertEquals(PERSISTENT_ID, capturedContext.persistentSessionId());
        assertEquals(SESSION_ID, capturedContext.clientSessionId());
        assertEquals(TEST_PUBLIC_SUBJECT, capturedContext.subjectId());
        assertEquals(TEST_EMAIL, capturedContext.email());

        //        assertThat(capturedContext.metadata(),
        // hasItem(MetadataPair.pair("phone_number_country_code", "+44")));

        // Verify the restricted section of the audit event
        // The txmaAuditEncoded value from headers should be included in the restricted section
        assertEquals(Optional.of(TXMA_ENCODED_HEADER_VALUE), capturedContext.txmaAuditEncoded());

        // Verify the extensions section of the audit event contains mfa-method field
        ArgumentCaptor<MetadataPair[]> metadataPairsCaptor =
                ArgumentCaptor.forClass(MetadataPair[].class);
        verify(auditService)
                .submitAuditEvent(
                        eq(AccountManagementAuditableEvent.AUTH_MFA_METHOD_MIGRATION_ATTEMPTED),
                        eq(capturedContext),
                        metadataPairsCaptor.capture());

        // Verify that the mfa-method field is included in the extensions section with value "SMS"
        boolean hasMfaMethodField = false;
        for (MetadataPair pair : metadataPairsCaptor.getValue()) {
            if (pair.key().equals("mfa-method") && pair.value().equals("SMS")) {
                hasMfaMethodField = true;
                break;
            }
        }
        assertTrue(
                hasMfaMethodField,
                "Audit event should contain mfa-method field with value 'SMS' in extensions section");

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
    }

    @Test
    void shouldReturn200AndCreateAuthAppMfa() throws Json.JsonException {
        var authAppBackup =
                MFAMethod.authAppMfaMethod(
                        TEST_CREDENTIAL, true, true, PriorityIdentifier.BACKUP, TEST_AUTH_APP_ID);
        when(mfaMethodsService.addBackupMfa(any(), any()))
                .thenReturn(Result.success(authAppBackup));

        var event =
                generateApiGatewayEvent(
                        PriorityIdentifier.BACKUP,
                        new RequestAuthAppMfaDetail(TEST_CREDENTIAL),
                        TEST_INTERNAL_SUBJECT);

        var headers =
                Map.ofEntries(
                        Map.entry(PersistentIdHelper.PERSISTENT_ID_HEADER_NAME, PERSISTENT_ID),
                        Map.entry(ClientSessionIdHelper.SESSION_ID_HEADER_NAME, SESSION_ID),
                        Map.entry(AuditHelper.TXMA_ENCODED_HEADER_NAME, TXMA_ENCODED_HEADER_VALUE),
                        Map.entry(SESSION_ID_HEADER, SESSION_ID));

        event.setHeaders(headers);

        var result = handler.handleRequest(event, context);

        ArgumentCaptor<MfaMethodCreateRequest.MfaMethod> mfaMethodCaptor =
                ArgumentCaptor.forClass(MfaMethodCreateRequest.MfaMethod.class);

        verify(mfaMethodsService).addBackupMfa(eq(TEST_EMAIL), mfaMethodCaptor.capture());
        var capturedRequest = mfaMethodCaptor.getValue();

        assertEquals(new RequestAuthAppMfaDetail(TEST_CREDENTIAL), capturedRequest.method());
        assertEquals(PriorityIdentifier.BACKUP, capturedRequest.priorityIdentifier());

        // Verify audit event is emitted with metadata pairs
        ArgumentCaptor<AuditContext> auditContextCaptor =
                ArgumentCaptor.forClass(AuditContext.class);
        verify(auditService)
                .submitAuditEvent(
                        eq(AccountManagementAuditableEvent.AUTH_MFA_METHOD_MIGRATION_ATTEMPTED),
                        auditContextCaptor.capture());

        AuditContext capturedContext = auditContextCaptor.getValue();

        // Create expected user object
        TxmaAuditUser expectedUser =
                TxmaAuditUser.user()
                        .withUserId(TEST_PUBLIC_SUBJECT)
                        .withEmail(TEST_EMAIL)
                        .withPhone(userProfile.getPhoneNumber())
                        .withIpAddress("123.123.123.123")
                        .withSessionId(null)
                        .withPersistentSessionId(PERSISTENT_ID)
                        .withGovukSigninJourneyId(SESSION_ID);

        System.out.println(capturedContext);

        // Verify the audit context matches the expected user data
        assertEquals(TEST_CLIENT_ID, capturedContext.clientId());

        // extensions
        assertThat(
                capturedContext.metadata(),
                hasItem(MetadataPair.pair("journey-type", JourneyType.ACCOUNT_MANAGEMENT)));
        //        assertThat(capturedContext.metadata(), hasItem(MetadataPair.pair("had-partial",
        // JourneyType.ACCOUNT_MANAGEMENT)));
        assertThat(
                capturedContext.metadata(),
                hasItem(MetadataPair.pair("mfa-type", MFAMethodType.AUTH_APP)));
        assertThat(
                capturedContext.metadata(),
                hasItem(MetadataPair.pair("migration-succeeded", true)));

        // user
        assertEquals(TEST_EMAIL, capturedContext.email());
        assertEquals(SESSION_ID, capturedContext.clientSessionId()); // govuk_signin_journey_id
        assertEquals("123.123.123.123", capturedContext.ipAddress());
        assertEquals(PERSISTENT_ID, capturedContext.persistentSessionId());
        assertEquals(expectedUser.getPhone(), capturedContext.phoneNumber());
        assertEquals(SESSION_ID, capturedContext.sessionId());
        assertEquals(TEST_PUBLIC_SUBJECT, capturedContext.subjectId());

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
    }

    @Test
    void shouldReturn400WhenPathParameterIsEmpty() {
        var event = new APIGatewayProxyRequestEvent();
        event.setPathParameters(Map.of());

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1001));
        assertThat(
                logging.events(),
                hasItem(
                        withMessageContaining(
                                "Subject missing from request prevents request being handled.")));
        verifyNoInteractions(sqsClient);
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
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1056));
        verifyNoInteractions(sqsClient);
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
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1001));
    }

    @Test
    void shouldReturn400WhenRequestToCreateNewDefault() {
        var event =
                generateApiGatewayEvent(
                        PriorityIdentifier.DEFAULT,
                        new RequestSmsMfaDetail(TEST_PHONE_NUMBER, TEST_OTP),
                        TEST_INTERNAL_SUBJECT);

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1080));
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
                                MfaCreateFailureReason.BACKUP_AND_DEFAULT_METHOD_ALREADY_EXIST));

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1068));
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

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.INVALID_PHONE_NUMBER));
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
                                MfaCreateFailureReason.BACKUP_AND_DEFAULT_METHOD_ALREADY_EXIST));

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1020));
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
        when(mfaMethodsService.addBackupMfa(any(), any()))
                .thenReturn(Result.failure(MfaCreateFailureReason.PHONE_NUMBER_ALREADY_EXISTS));

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1069));
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

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1070));
    }

    @Test
    void shouldReturn500WhenReturnedMfaMethodDoesNotConvertToMfaResponse() {
        var mfaMethodWithInvalidMfaType =
                new MFAMethod("invalid mfa type", TEST_CREDENTIAL, true, true, "updated-timestamp");
        var event =
                generateApiGatewayEvent(
                        PriorityIdentifier.BACKUP,
                        new RequestAuthAppMfaDetail(TEST_CREDENTIAL),
                        TEST_INTERNAL_SUBJECT);
        when(dynamoService.getOptionalUserProfileFromPublicSubject(TEST_PUBLIC_SUBJECT))
                .thenReturn(Optional.of(userProfile));
        when(mfaMethodsService.addBackupMfa(any(), any()))
                .thenReturn(Result.success(mfaMethodWithInvalidMfaType));

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(500));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1071));
        verifyNoInteractions(sqsClient);
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
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1079));
    }

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
        proxyRequestContext.setIdentity(identityWithSourceIp("123.123.123.123"));

        return new APIGatewayProxyRequestEvent()
                .withPathParameters(Map.of("publicSubjectId", TEST_PUBLIC_SUBJECT))
                .withBody(body)
                .withRequestContext(proxyRequestContext)
                .withHeaders(VALID_HEADERS);
    }
}
