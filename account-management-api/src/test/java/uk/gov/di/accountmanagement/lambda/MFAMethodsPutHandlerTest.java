package uk.gov.di.accountmanagement.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.google.gson.JsonParser;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.accountmanagement.entity.NotificationType;
import uk.gov.di.accountmanagement.entity.NotifyRequest;
import uk.gov.di.accountmanagement.services.AwsSqsClient;
import uk.gov.di.accountmanagement.services.CodeStorageService;
import uk.gov.di.accountmanagement.services.MfaMethodsMigrationService;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.PriorityIdentifier;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethod;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodUpdateIdentifier;
import uk.gov.di.authentication.shared.entity.mfa.request.MfaMethodUpdateRequest;
import uk.gov.di.authentication.shared.entity.mfa.request.RequestAuthAppMfaDetail;
import uk.gov.di.authentication.shared.entity.mfa.request.RequestSmsMfaDetail;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.helpers.LocaleHelper;
import uk.gov.di.authentication.shared.helpers.SaltHelper;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.SerializationService;
import uk.gov.di.authentication.shared.services.mfa.MFAMethodsService;
import uk.gov.di.authentication.shared.services.mfa.MfaMigrationFailureReason;
import uk.gov.di.authentication.shared.services.mfa.MfaUpdateFailure;
import uk.gov.di.authentication.shared.services.mfa.MfaUpdateFailureReason;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.AdditionalMatchers.not;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.di.accountmanagement.constants.AccountManagementConstants.AUDIT_EVENT_COMPONENT_ID_HOME;
import static uk.gov.di.accountmanagement.domain.AccountManagementAuditableEvent.AUTH_CODE_VERIFIED;
import static uk.gov.di.accountmanagement.domain.AccountManagementAuditableEvent.AUTH_INVALID_CODE_SENT;
import static uk.gov.di.accountmanagement.domain.AccountManagementAuditableEvent.AUTH_MFA_METHOD_SWITCH_COMPLETED;
import static uk.gov.di.accountmanagement.domain.AccountManagementAuditableEvent.AUTH_MFA_METHOD_SWITCH_FAILED;
import static uk.gov.di.accountmanagement.domain.AccountManagementAuditableEvent.AUTH_UPDATE_PHONE_NUMBER;
import static uk.gov.di.accountmanagement.domain.AccountManagementAuditableEvent.AUTH_UPDATE_PROFILE_AUTH_APP;
import static uk.gov.di.accountmanagement.entity.NotificationType.CHANGED_DEFAULT_MFA;
import static uk.gov.di.accountmanagement.entity.NotificationType.VERIFY_PHONE_NUMBER;
import static uk.gov.di.accountmanagement.helpers.CommonTestVariables.IP_ADDRESS;
import static uk.gov.di.accountmanagement.helpers.CommonTestVariables.PERSISTENT_ID;
import static uk.gov.di.accountmanagement.helpers.CommonTestVariables.SESSION_ID;
import static uk.gov.di.accountmanagement.helpers.CommonTestVariables.TXMA_ENCODED_HEADER_VALUE;
import static uk.gov.di.accountmanagement.helpers.CommonTestVariables.VALID_HEADERS;
import static uk.gov.di.authentication.shared.entity.JourneyType.ACCOUNT_MANAGEMENT;
import static uk.gov.di.authentication.shared.entity.PriorityIdentifier.BACKUP;
import static uk.gov.di.authentication.shared.entity.PriorityIdentifier.DEFAULT;
import static uk.gov.di.authentication.shared.services.AuditService.MetadataPair.pair;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.BACKUP_SMS_METHOD;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.DEFAULT_SMS_METHOD;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.INTERNATIONAL_MOBILE_NUMBER;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.UK_MOBILE_NUMBER;
import static uk.gov.di.authentication.sharedtest.helper.RequestEventHelper.identityWithSourceIp;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class MFAMethodsPutHandlerTest {
    private final Json objectMapper = SerializationService.getInstance();

    private static final ConfigurationService configurationService =
            mock(ConfigurationService.class);
    private static final CodeStorageService codeStorageService = mock(CodeStorageService.class);
    private static final MFAMethodsService mfaMethodsService = mock(MFAMethodsService.class);
    private static final AuditService auditService = mock(AuditService.class);
    private static final DynamoService dynamoService = mock(DynamoService.class);
    private static final AuthenticationService authenticationService =
            mock(AuthenticationService.class);
    private final AwsSqsClient sqsClient = mock(AwsSqsClient.class);
    private static final Context context = mock(Context.class);
    private static final MfaMethodsMigrationService mfaMethodsMigrationService =
            mock(MfaMethodsMigrationService.class);
    private static final String TEST_PUBLIC_SUBJECT = new Subject().getValue();
    private static final String TEST_CLIENT = "test-client";
    private static final byte[] TEST_SALT = SaltHelper.generateNewSalt();
    private static final String EMAIL = "joe.bloggs@digital.cabinet-office.gov.uk";
    private static final UserProfile userProfile =
            new UserProfile()
                    .withSubjectID(TEST_PUBLIC_SUBJECT)
                    .withEmail(EMAIL)
                    .withMfaMethodsMigrated(true);
    private static final String TEST_INTERNAL_SUBJECT =
            ClientSubjectHelper.calculatePairwiseIdentifier(
                    TEST_PUBLIC_SUBJECT, "test.account.gov.uk", TEST_SALT);
    private static final String MFA_IDENTIFIER = "some-mfa-identifier";
    public static final String TEST_OTP = "123456";
    public static final String INCORRECT_OTP = "111111";
    private static final AuditContext BASE_AUDIT_CONTEXT =
            AuditContext.emptyAuditContext()
                    .withTxmaAuditEncoded(Optional.of(TXMA_ENCODED_HEADER_VALUE))
                    .withEmail(EMAIL)
                    .withClientSessionId(SESSION_ID)
                    .withSubjectId(TEST_INTERNAL_SUBJECT)
                    .withIpAddress(IP_ADDRESS)
                    .withTxmaAuditEncoded(Optional.of(TXMA_ENCODED_HEADER_VALUE))
                    .withPersistentSessionId(PERSISTENT_ID)
                    .withMetadataItem(pair("journey-type", ACCOUNT_MANAGEMENT.getValue()));

    private MFAMethodsPutHandler handler;

    @BeforeEach
    void setUp() {
        reset(
                configurationService,
                codeStorageService,
                mfaMethodsService,
                auditService,
                dynamoService,
                authenticationService,
                sqsClient,
                mfaMethodsMigrationService);

        when(configurationService.isMfaMethodManagementApiEnabled()).thenReturn(true);
        when(configurationService.isAccountManagementInternationalSmsEnabled()).thenReturn(true);
        when(configurationService.getEnvironment()).thenReturn("test");
        when(configurationService.getInternalSectorUri()).thenReturn("https://test.account.gov.uk");
        when(authenticationService.getOrGenerateSalt(userProfile)).thenReturn(TEST_SALT);
        when(dynamoService.getOrGenerateSalt(userProfile)).thenReturn(TEST_SALT);
        when(authenticationService.getOptionalUserProfileFromPublicSubject(TEST_PUBLIC_SUBJECT))
                .thenReturn(Optional.of(userProfile));
        handler =
                new MFAMethodsPutHandler(
                        configurationService,
                        mfaMethodsService,
                        authenticationService,
                        codeStorageService,
                        sqsClient,
                        auditService,
                        dynamoService,
                        mfaMethodsMigrationService);
    }

    @Test
    void shouldReturn200WithUpdatedMethodWhenFeatureFlagEnabled() throws Json.JsonException {
        var phoneNumber = UK_MOBILE_NUMBER;
        var event = requestWithPublicSubjectAndMfaIdentifier(TEST_PUBLIC_SUBJECT, MFA_IDENTIFIER);
        var eventWithUpdateRequest = event.withBody(updateSmsRequest(phoneNumber, TEST_OTP));
        setupValidOtpForEmail(TEST_OTP, EMAIL);

        var updatedMfaMethod =
                MFAMethod.smsMfaMethod(
                        true, true, phoneNumber, PriorityIdentifier.DEFAULT, MFA_IDENTIFIER);
        when(mfaMethodsService.getMfaMethod(EMAIL, MFA_IDENTIFIER))
                .thenReturn(
                        Result.success(
                                new MFAMethodsService.GetMfaResult(
                                        DEFAULT_SMS_METHOD, List.of(DEFAULT_SMS_METHOD))));
        var expectedDatabaseUpdateRequest =
                MfaMethodUpdateRequest.from(
                        PriorityIdentifier.DEFAULT, new RequestSmsMfaDetail(phoneNumber, TEST_OTP));
        when(mfaMethodsService.updateMfaMethod(
                        eq(EMAIL), any(), any(), eq(expectedDatabaseUpdateRequest)))
                .thenReturn(
                        Result.success(
                                new MFAMethodsService.MfaUpdateResponse(
                                        List.of(updatedMfaMethod),
                                        MFAMethodUpdateIdentifier.CHANGED_DEFAULT_MFA)));

        var result = handler.handleRequest(eventWithUpdateRequest, context);

        assertEquals(200, result.getStatusCode());
        var expectedResponse =
                format(
                        """
                [{
                  "mfaIdentifier": "%s",
                  "priorityIdentifier": "DEFAULT",
                  "methodVerified": true,
                  "method": {
                    "mfaMethodType": "SMS",
                    "phoneNumber": "%s"
                  }
                }]
                """,
                        MFA_IDENTIFIER, phoneNumber);
        var expectedResponseParsedToString =
                JsonParser.parseString(expectedResponse).getAsJsonArray().toString();
        assertEquals(expectedResponseParsedToString, result.getBody());

        verify(sqsClient)
                .send(
                        objectMapper.writeValueAsString(
                                new NotifyRequest(
                                        EMAIL,
                                        CHANGED_DEFAULT_MFA,
                                        LocaleHelper.SupportedLanguage.EN)));
        verify(authenticationService).getOptionalUserProfileFromPublicSubject(TEST_PUBLIC_SUBJECT);
        verify(codeStorageService)
                .isValidOtpCode(EMAIL, TEST_OTP, NotificationType.VERIFY_PHONE_NUMBER);
        verify(mfaMethodsService)
                .updateMfaMethod(
                        eq(EMAIL),
                        eq(DEFAULT_SMS_METHOD),
                        eq(List.of(DEFAULT_SMS_METHOD)),
                        eq(expectedDatabaseUpdateRequest));
    }

    @Test
    void shouldReturn200WithUpdatedMethodWhenFeatureFlagEnabledAndUserMigrationSuccessful()
            throws Json.JsonException {
        var nonMigratedEmail = "non-migrated-email@example.com";
        var nonMigratedUser =
                new UserProfile()
                        .withMfaMethodsMigrated(false)
                        .withEmail(nonMigratedEmail)
                        .withSubjectID(TEST_PUBLIC_SUBJECT);
        when(authenticationService.getOrGenerateSalt(nonMigratedUser)).thenReturn(TEST_SALT);
        var phoneNumber = UK_MOBILE_NUMBER;
        var event = requestWithPublicSubjectAndMfaIdentifier(TEST_PUBLIC_SUBJECT, MFA_IDENTIFIER);
        var eventWithUpdateRequest = event.withBody(updateSmsRequest(phoneNumber, TEST_OTP));
        setupValidOtpForEmail(TEST_OTP, nonMigratedEmail);

        when(authenticationService.getOptionalUserProfileFromPublicSubject(TEST_PUBLIC_SUBJECT))
                .thenReturn(Optional.of(nonMigratedUser));

        var updatedMfaMethod =
                MFAMethod.smsMfaMethod(
                        true, true, phoneNumber, PriorityIdentifier.DEFAULT, MFA_IDENTIFIER);
        when(mfaMethodsService.getMfaMethod(nonMigratedEmail, MFA_IDENTIFIER))
                .thenReturn(
                        Result.success(
                                new MFAMethodsService.GetMfaResult(
                                        DEFAULT_SMS_METHOD, List.of(DEFAULT_SMS_METHOD))));
        var expectedDatabaseUpdatedRequest =
                MfaMethodUpdateRequest.from(
                        PriorityIdentifier.DEFAULT, new RequestSmsMfaDetail(phoneNumber, TEST_OTP));
        when(mfaMethodsService.updateMfaMethod(
                        eq(nonMigratedEmail), any(), any(), eq(expectedDatabaseUpdatedRequest)))
                .thenReturn(
                        Result.success(
                                new MFAMethodsService.MfaUpdateResponse(
                                        List.of(updatedMfaMethod),
                                        MFAMethodUpdateIdentifier.CHANGED_DEFAULT_MFA)));
        when(mfaMethodsService.migrateMfaCredentialsForUser(nonMigratedUser))
                .thenReturn(Result.success(false));

        var result = handler.handleRequest(eventWithUpdateRequest, context);

        assertEquals(200, result.getStatusCode());
        var expectedResponse =
                format(
                        """
                [{
                  "mfaIdentifier": "%s",
                  "priorityIdentifier": "DEFAULT",
                  "methodVerified": true,
                  "method": {
                    "mfaMethodType": "SMS",
                    "phoneNumber": "%s"
                  }
                }]
                """,
                        MFA_IDENTIFIER, phoneNumber);
        var expectedResponseParsedToString =
                JsonParser.parseString(expectedResponse).getAsJsonArray().toString();
        assertEquals(expectedResponseParsedToString, result.getBody());

        verify(sqsClient)
                .send(
                        objectMapper.writeValueAsString(
                                new NotifyRequest(
                                        nonMigratedEmail,
                                        CHANGED_DEFAULT_MFA,
                                        LocaleHelper.SupportedLanguage.EN)));
        verify(authenticationService).getOptionalUserProfileFromPublicSubject(TEST_PUBLIC_SUBJECT);
        verify(codeStorageService)
                .isValidOtpCode(nonMigratedEmail, TEST_OTP, NotificationType.VERIFY_PHONE_NUMBER);
        verify(mfaMethodsService)
                .updateMfaMethod(
                        eq(nonMigratedEmail),
                        eq(DEFAULT_SMS_METHOD),
                        eq(List.of(DEFAULT_SMS_METHOD)),
                        eq(expectedDatabaseUpdatedRequest));
        verify(mfaMethodsMigrationService)
                .migrateMfaCredentialsForUserIfRequired(any(), any(), any(), any());
    }

    private static Stream<Arguments> validEmailNotificationIdentifiers() {
        return Stream.of(
                Arguments.of(
                        MFAMethodUpdateIdentifier.CHANGED_AUTHENTICATOR_APP,
                        NotificationType.CHANGED_AUTHENTICATOR_APP),
                Arguments.of(
                        MFAMethodUpdateIdentifier.CHANGED_DEFAULT_MFA,
                        NotificationType.CHANGED_DEFAULT_MFA),
                Arguments.of(
                        MFAMethodUpdateIdentifier.SWITCHED_MFA_METHODS,
                        NotificationType.SWITCHED_MFA_METHODS));
    }

    @ParameterizedTest
    @MethodSource("validEmailNotificationIdentifiers")
    void shouldSendAppropriateEmailNotificationUponSuccessWhenFeatureFlagEnabled(
            MFAMethodUpdateIdentifier emailNotificationIdentifier,
            NotificationType notificationType)
            throws Json.JsonException {
        var phoneNumber = UK_MOBILE_NUMBER;
        var event = requestWithPublicSubjectAndMfaIdentifier(TEST_PUBLIC_SUBJECT, MFA_IDENTIFIER);
        var eventWithUpdateRequest = event.withBody(updateSmsRequest(phoneNumber, TEST_OTP));
        setupValidOtpForEmail(TEST_OTP, EMAIL);

        var updatedMfaMethod =
                MFAMethod.smsMfaMethod(
                        true, true, phoneNumber, PriorityIdentifier.DEFAULT, MFA_IDENTIFIER);
        when(mfaMethodsService.getMfaMethod(EMAIL, MFA_IDENTIFIER))
                .thenReturn(
                        Result.success(
                                new MFAMethodsService.GetMfaResult(
                                        DEFAULT_SMS_METHOD, List.of(DEFAULT_SMS_METHOD))));
        var expectedDatabaseUpdateRequest =
                MfaMethodUpdateRequest.from(
                        PriorityIdentifier.DEFAULT, new RequestSmsMfaDetail(phoneNumber, TEST_OTP));
        when(mfaMethodsService.updateMfaMethod(
                        eq(EMAIL), any(), any(), eq(expectedDatabaseUpdateRequest)))
                .thenReturn(
                        Result.success(
                                new MFAMethodsService.MfaUpdateResponse(
                                        List.of(updatedMfaMethod), emailNotificationIdentifier)));

        var result = handler.handleRequest(eventWithUpdateRequest, context);

        assertEquals(200, result.getStatusCode());
        var expectedResponse =
                format(
                        """
                [{
                  "mfaIdentifier": "%s",
                  "priorityIdentifier": "DEFAULT",
                  "methodVerified": true,
                  "method": {
                    "mfaMethodType": "SMS",
                    "phoneNumber": "%s"
                  }
                }]
                """,
                        MFA_IDENTIFIER, phoneNumber);
        var expectedResponseParsedToString =
                JsonParser.parseString(expectedResponse).getAsJsonArray().toString();
        assertEquals(expectedResponseParsedToString, result.getBody());

        verify(sqsClient)
                .send(
                        objectMapper.writeValueAsString(
                                new NotifyRequest(
                                        EMAIL,
                                        notificationType,
                                        LocaleHelper.SupportedLanguage.EN)));
        verify(authenticationService).getOptionalUserProfileFromPublicSubject(TEST_PUBLIC_SUBJECT);
        verify(codeStorageService)
                .isValidOtpCode(EMAIL, TEST_OTP, NotificationType.VERIFY_PHONE_NUMBER);
        verify(mfaMethodsService)
                .updateMfaMethod(
                        eq(EMAIL),
                        eq(DEFAULT_SMS_METHOD),
                        eq(List.of(DEFAULT_SMS_METHOD)),
                        eq(expectedDatabaseUpdateRequest));
    }

    @CsvSource({"500", "404", "200"})
    @Test
    void shouldRaiseSwitchCompletedAuditEvent() {
        var phoneNumber = UK_MOBILE_NUMBER;
        var event = requestWithPublicSubjectAndMfaIdentifier(TEST_PUBLIC_SUBJECT, MFA_IDENTIFIER);
        var eventWithUpdateRequest = event.withBody(updateSmsRequest(phoneNumber, TEST_OTP));
        setupValidOtpForEmail(TEST_OTP, EMAIL);

        var defaultMfaMethod =
                MFAMethod.smsMfaMethod(
                        true, true, phoneNumber, PriorityIdentifier.DEFAULT, MFA_IDENTIFIER);
        var backupMfaMethod =
                MFAMethod.authAppMfaMethod(
                        "auth-app-credential-1",
                        true,
                        true,
                        PriorityIdentifier.BACKUP,
                        "auth-app-identifier-1");
        var postUpdateMfaMethods = List.of(defaultMfaMethod, backupMfaMethod);

        when(mfaMethodsService.getMfaMethod(EMAIL, MFA_IDENTIFIER))
                .thenReturn(
                        Result.success(
                                new MFAMethodsService.GetMfaResult(
                                        defaultMfaMethod, postUpdateMfaMethods)));

        var expectedDatabaseUpdateRequest =
                MfaMethodUpdateRequest.from(
                        PriorityIdentifier.DEFAULT, new RequestSmsMfaDetail(phoneNumber, TEST_OTP));
        when(mfaMethodsService.updateMfaMethod(
                        eq(EMAIL), any(), any(), eq(expectedDatabaseUpdateRequest)))
                .thenReturn(
                        Result.success(
                                new MFAMethodsService.MfaUpdateResponse(
                                        postUpdateMfaMethods,
                                        MFAMethodUpdateIdentifier.SWITCHED_MFA_METHODS)));

        var result = handler.handleRequest(eventWithUpdateRequest, context);

        assertEquals(200, result.getStatusCode());

        var expectedAuditContext =
                BASE_AUDIT_CONTEXT
                        .withPhoneNumber(UK_MOBILE_NUMBER)
                        .withMetadataItem(pair("mfa-type", defaultMfaMethod.getMfaMethodType()));

        verify(auditService)
                .submitAuditEvent(
                        AUTH_MFA_METHOD_SWITCH_COMPLETED,
                        expectedAuditContext,
                        AUDIT_EVENT_COMPONENT_ID_HOME);
    }

    private static Stream<MFAMethodUpdateIdentifier> phoneNumberUpdateTypeIdentifiers() {
        return Stream.of(
                MFAMethodUpdateIdentifier.CHANGED_SMS,
                MFAMethodUpdateIdentifier.CHANGED_DEFAULT_MFA);
    }

    @ParameterizedTest
    @MethodSource("phoneNumberUpdateTypeIdentifiers")
    void shouldRaiseUpdatePhoneNumberAuditEvent(MFAMethodUpdateIdentifier updateTypeIdentifier) {
        var phoneNumber = UK_MOBILE_NUMBER;
        var event = requestWithPublicSubjectAndMfaIdentifier(TEST_PUBLIC_SUBJECT, MFA_IDENTIFIER);
        var eventWithUpdateRequest = event.withBody(updateSmsRequest(phoneNumber, TEST_OTP));
        setupValidOtpForEmail(TEST_OTP, EMAIL);

        var defaultMfaMethod =
                MFAMethod.smsMfaMethod(
                        true, true, phoneNumber, PriorityIdentifier.DEFAULT, MFA_IDENTIFIER);
        var backupMfaMethod =
                MFAMethod.authAppMfaMethod(
                        "auth-app-credential-1",
                        true,
                        true,
                        PriorityIdentifier.BACKUP,
                        "auth-app-identifier-1");
        var postUpdateMfaMethods = List.of(defaultMfaMethod, backupMfaMethod);

        when(mfaMethodsService.getMfaMethod(EMAIL, MFA_IDENTIFIER))
                .thenReturn(
                        Result.success(
                                new MFAMethodsService.GetMfaResult(
                                        defaultMfaMethod, postUpdateMfaMethods)));
        var expectedDatabaseUpdateRequest =
                MfaMethodUpdateRequest.from(
                        PriorityIdentifier.DEFAULT, new RequestSmsMfaDetail(phoneNumber, TEST_OTP));
        when(mfaMethodsService.updateMfaMethod(
                        eq(EMAIL), any(), any(), eq(expectedDatabaseUpdateRequest)))
                .thenReturn(
                        Result.success(
                                new MFAMethodsService.MfaUpdateResponse(
                                        postUpdateMfaMethods, updateTypeIdentifier)));

        var result = handler.handleRequest(eventWithUpdateRequest, context);

        assertEquals(200, result.getStatusCode());

        var expectedAuditContext =
                BASE_AUDIT_CONTEXT
                        .withPhoneNumber(UK_MOBILE_NUMBER)
                        .withMetadataItem(
                                pair("mfa-method", defaultMfaMethod.getPriority().toLowerCase()));

        verify(auditService)
                .submitAuditEvent(
                        AUTH_UPDATE_PHONE_NUMBER,
                        expectedAuditContext,
                        AUDIT_EVENT_COMPONENT_ID_HOME);
    }

    @Test
    void shouldRaiseOnlySwitchCompletedAuditEventWhenSwitchingBetweenSmsMethodsSuccessful() {
        setupValidOtpForEmail(TEST_OTP, EMAIL);

        var existingBackupNumber = UK_MOBILE_NUMBER;
        var existingDefaultNumber = "+447316763843";

        when(mfaMethodsService.getMfaMethod(EMAIL, MFA_IDENTIFIER))
                .thenReturn(
                        Result.success(
                                new MFAMethodsService.GetMfaResult(
                                        DEFAULT_SMS_METHOD, List.of(DEFAULT_SMS_METHOD))));

        var event = requestWithPublicSubjectAndMfaIdentifier(TEST_PUBLIC_SUBJECT, MFA_IDENTIFIER);
        var eventWithUpdateRequest =
                event.withBody(updateSmsRequest(existingBackupNumber, TEST_OTP));

        var expectedDatabaseUpdateRequest =
                MfaMethodUpdateRequest.from(
                        PriorityIdentifier.DEFAULT,
                        new RequestSmsMfaDetail(existingBackupNumber, TEST_OTP));
        var defaultMethodAfterSwitch =
                MFAMethod.smsMfaMethod(
                        true,
                        true,
                        existingBackupNumber,
                        PriorityIdentifier.DEFAULT,
                        MFA_IDENTIFIER);
        var backupMethodAfterSwitch =
                MFAMethod.smsMfaMethod(
                        true,
                        true,
                        existingDefaultNumber,
                        PriorityIdentifier.BACKUP,
                        "sms-identifier-2");

        when(mfaMethodsService.updateMfaMethod(
                        eq(EMAIL), any(), any(), eq(expectedDatabaseUpdateRequest)))
                .thenReturn(
                        Result.success(
                                new MFAMethodsService.MfaUpdateResponse(
                                        List.of(defaultMethodAfterSwitch, backupMethodAfterSwitch),
                                        MFAMethodUpdateIdentifier.SWITCHED_MFA_METHODS)));

        var result = handler.handleRequest(eventWithUpdateRequest, context);

        assertEquals(200, result.getStatusCode());

        var expectedAuditContext =
                BASE_AUDIT_CONTEXT
                        .withPhoneNumber(existingBackupNumber)
                        .withMetadataItem(
                                pair("mfa-type", defaultMethodAfterSwitch.getMfaMethodType()));

        verify(auditService)
                .submitAuditEvent(
                        AUTH_MFA_METHOD_SWITCH_COMPLETED,
                        expectedAuditContext,
                        AUDIT_EVENT_COMPONENT_ID_HOME);

        verify(auditService, never()).submitAuditEvent(eq(AUTH_UPDATE_PHONE_NUMBER), any(), any());
    }

    @Test
    void shouldNotRaiseUpdatePhoneNumberAuditEventWhenChangedDefaultAuthAppMfa() {
        when(mfaMethodsService.getMfaMethod(EMAIL, MFA_IDENTIFIER))
                .thenReturn(
                        Result.success(
                                new MFAMethodsService.GetMfaResult(
                                        DEFAULT_SMS_METHOD, List.of(DEFAULT_SMS_METHOD))));

        var credential = "some credential";
        var event = requestWithPublicSubjectAndMfaIdentifier(TEST_PUBLIC_SUBJECT, MFA_IDENTIFIER);
        var eventWithUpdateRequest = event.withBody(updateAuthAppRequest(credential));

        var defaultMfaMethod =
                MFAMethod.authAppMfaMethod(
                        "auth-app-credential-1",
                        true,
                        true,
                        PriorityIdentifier.DEFAULT,
                        MFA_IDENTIFIER);
        var backupMfaMethod =
                MFAMethod.smsMfaMethod(
                        true,
                        true,
                        UK_MOBILE_NUMBER,
                        PriorityIdentifier.BACKUP,
                        "sms-identifier-1");
        var postUpdateMfaMethods = List.of(defaultMfaMethod, backupMfaMethod);
        var expectedDatabaseUpdateRequest =
                MfaMethodUpdateRequest.from(
                        PriorityIdentifier.DEFAULT, new RequestAuthAppMfaDetail(credential));
        when(mfaMethodsService.updateMfaMethod(
                        eq(EMAIL), any(), any(), eq(expectedDatabaseUpdateRequest)))
                .thenReturn(
                        Result.success(
                                new MFAMethodsService.MfaUpdateResponse(
                                        postUpdateMfaMethods,
                                        MFAMethodUpdateIdentifier.CHANGED_DEFAULT_MFA)));

        var result = handler.handleRequest(eventWithUpdateRequest, context);

        assertEquals(200, result.getStatusCode());

        verify(auditService, never()).submitAuditEvent(eq(AUTH_UPDATE_PHONE_NUMBER), any(), any());
    }

    @Test
    void shouldRaiseAuthCodeVerifiedAuditEvent() {
        setupValidOtpForEmail(TEST_OTP, EMAIL);
        when(mfaMethodsService.getMfaMethod(EMAIL, MFA_IDENTIFIER))
                .thenReturn(
                        Result.success(
                                new MFAMethodsService.GetMfaResult(
                                        DEFAULT_SMS_METHOD, List.of(DEFAULT_SMS_METHOD))));

        var event = requestWithPublicSubjectAndMfaIdentifier(TEST_PUBLIC_SUBJECT, MFA_IDENTIFIER);
        var eventWithUpdateRequest =
                event.withBody(updateSmsRequest(DEFAULT_SMS_METHOD.getDestination(), TEST_OTP));

        var expectedDatabaseUpdateRequest =
                MfaMethodUpdateRequest.from(
                        PriorityIdentifier.DEFAULT,
                        new RequestSmsMfaDetail(DEFAULT_SMS_METHOD.getDestination(), TEST_OTP));
        when(mfaMethodsService.updateMfaMethod(
                        eq(EMAIL), any(), any(), eq(expectedDatabaseUpdateRequest)))
                .thenReturn(
                        Result.success(
                                new MFAMethodsService.MfaUpdateResponse(
                                        List.of(DEFAULT_SMS_METHOD),
                                        MFAMethodUpdateIdentifier.CHANGED_DEFAULT_MFA)));

        handler.handleRequest(eventWithUpdateRequest, context);

        var expectedAuditContext =
                BASE_AUDIT_CONTEXT
                        .withPhoneNumber(UK_MOBILE_NUMBER)
                        .withMetadataItem(pair("mfa-type", DEFAULT_SMS_METHOD.getMfaMethodType()))
                        .withMetadataItem(pair("MFACodeEntered", TEST_OTP))
                        .withMetadataItem(pair("notification-type", "MFA_SMS"))
                        .withMetadataItem(pair("account-recovery", "false"))
                        .withMetadataItem(pair("journey-type", ACCOUNT_MANAGEMENT.getValue()))
                        .withMetadataItem(
                                pair("mfa-method", DEFAULT_SMS_METHOD.getPriority().toLowerCase()))
                        .withMetadataItem(pair("mfa-type", DEFAULT_SMS_METHOD.getMfaMethodType()));
        // journey type repeated here (also in base context)- to fix
        // mfa type also repeated - to fix

        verify(auditService)
                .submitAuditEvent(
                        AUTH_CODE_VERIFIED, expectedAuditContext, AUDIT_EVENT_COMPONENT_ID_HOME);
    }

    @Test
    void shouldNotRaiseAuthCodeVerifiedAuditEventWhenOtpIncorrect() {
        var event = requestWithPublicSubjectAndMfaIdentifier(TEST_PUBLIC_SUBJECT, MFA_IDENTIFIER);
        var eventWithUpdateRequest =
                event.withBody(
                        updateSmsRequest(DEFAULT_SMS_METHOD.getDestination(), INCORRECT_OTP));
        when(codeStorageService.isValidOtpCode(EMAIL, INCORRECT_OTP, VERIFY_PHONE_NUMBER))
                .thenReturn(false);
        when(mfaMethodsService.getMfaMethod(EMAIL, MFA_IDENTIFIER))
                .thenReturn(
                        Result.success(
                                new MFAMethodsService.GetMfaResult(
                                        DEFAULT_SMS_METHOD, List.of(DEFAULT_SMS_METHOD))));

        handler.handleRequest(eventWithUpdateRequest, context);

        verify(auditService, never()).submitAuditEvent(eq(AUTH_CODE_VERIFIED), any());
    }

    private static Stream<Arguments> migrationFailureReasonsToExpectedStatusCodes() {
        return Stream.of(
                Arguments.of(MfaMigrationFailureReason.UNEXPECTED_ERROR_RETRIEVING_METHODS, 500),
                Arguments.of(MfaMigrationFailureReason.NO_CREDENTIALS_FOUND_FOR_USER, 404),
                Arguments.of(MfaMigrationFailureReason.ALREADY_MIGRATED, 200));
    }

    @ParameterizedTest
    @MethodSource("migrationFailureReasonsToExpectedStatusCodes")
    void shouldReturnAppropriateResponseWhenUserMigrationNotSuccessful(
            MfaMigrationFailureReason migrationFailureReason, int expectedStatusCode)
            throws Json.JsonException {
        var nonMigratedEmail = "non-migrated-email@example.com";
        var nonMigratedUser =
                new UserProfile()
                        .withMfaMethodsMigrated(false)
                        .withEmail(nonMigratedEmail)
                        .withSubjectID(TEST_PUBLIC_SUBJECT);
        when(authenticationService.getOrGenerateSalt(nonMigratedUser)).thenReturn(TEST_SALT);
        var phoneNumber = UK_MOBILE_NUMBER;
        var event = requestWithPublicSubjectAndMfaIdentifier(TEST_PUBLIC_SUBJECT, MFA_IDENTIFIER);
        var eventWithUpdateRequest = event.withBody(updateSmsRequest(phoneNumber, TEST_OTP));
        setupValidOtpForEmail(TEST_OTP, nonMigratedEmail);

        when(authenticationService.getOptionalUserProfileFromPublicSubject(TEST_PUBLIC_SUBJECT))
                .thenReturn(Optional.of(nonMigratedUser));

        when(mfaMethodsService.getMfaMethod(nonMigratedEmail, MFA_IDENTIFIER))
                .thenReturn(
                        Result.success(
                                new MFAMethodsService.GetMfaResult(
                                        DEFAULT_SMS_METHOD, List.of(DEFAULT_SMS_METHOD))));

        var updatedMfaMethod =
                MFAMethod.smsMfaMethod(
                        true, true, phoneNumber, PriorityIdentifier.DEFAULT, MFA_IDENTIFIER);
        var expectedDatabaseUpdateRequest =
                MfaMethodUpdateRequest.from(
                        PriorityIdentifier.DEFAULT, new RequestSmsMfaDetail(phoneNumber, TEST_OTP));
        when(mfaMethodsService.updateMfaMethod(
                        eq(nonMigratedEmail), any(), any(), eq(expectedDatabaseUpdateRequest)))
                .thenReturn(
                        Result.success(
                                new MFAMethodsService.MfaUpdateResponse(
                                        List.of(updatedMfaMethod),
                                        MFAMethodUpdateIdentifier.CHANGED_DEFAULT_MFA)));
        when(mfaMethodsService.migrateMfaCredentialsForUser(nonMigratedUser))
                .thenReturn(Result.failure(migrationFailureReason));
        var expectedGateway = new APIGatewayProxyResponseEvent().withStatusCode(expectedStatusCode);
        if (expectedStatusCode != 200) {
            when(mfaMethodsMigrationService.migrateMfaCredentialsForUserIfRequired(
                            any(), any(), any(), any()))
                    .thenReturn(Optional.of(expectedGateway));
        } else {
            when(mfaMethodsMigrationService.migrateMfaCredentialsForUserIfRequired(
                            any(), any(), any(), any()))
                    .thenReturn(Optional.empty());
        }

        var result = handler.handleRequest(eventWithUpdateRequest, context);

        assertEquals(expectedStatusCode, result.getStatusCode());

        if (expectedStatusCode == 200) {
            var expectedResponseIfSuccess =
                    format(
                            """
                    [{
                      "mfaIdentifier": "%s",
                      "priorityIdentifier": "DEFAULT",
                      "methodVerified": true,
                      "method": {
                        "mfaMethodType": "SMS",
                        "phoneNumber": "%s"
                      }
                    }]
                    """,
                            MFA_IDENTIFIER, phoneNumber);
            var expectedResponseParsedToString =
                    JsonParser.parseString(expectedResponseIfSuccess).getAsJsonArray().toString();
            assertEquals(expectedResponseParsedToString, result.getBody());

            verify(sqsClient)
                    .send(
                            objectMapper.writeValueAsString(
                                    new NotifyRequest(
                                            nonMigratedEmail,
                                            CHANGED_DEFAULT_MFA,
                                            LocaleHelper.SupportedLanguage.EN)));
        } else {
            verify(sqsClient, never()).send(any());
        }

        if (migrationFailureReason == MfaMigrationFailureReason.ALREADY_MIGRATED) {
            verify(auditService)
                    .submitAuditEvent(
                            eq(AUTH_UPDATE_PHONE_NUMBER),
                            any(AuditContext.class),
                            eq(AUDIT_EVENT_COMPONENT_ID_HOME));
        } else {
            verifyNoInteractions(auditService);
        }
        verify(auditService, never())
                .submitAuditEvent(
                        not(eq(AUTH_CODE_VERIFIED)), any(), any(AuditService.MetadataPair[].class));
    }

    private static Stream<Arguments> updateFailureReasonsToExpectedResponses() {
        return Stream.of(
                Arguments.of(
                        MfaUpdateFailureReason.CANNOT_CHANGE_TYPE_OF_MFA_METHOD,
                        400,
                        Optional.of(ErrorResponse.CANNOT_CHANGE_MFA_TYPE)),
                Arguments.of(
                        MfaUpdateFailureReason.REQUEST_TO_UPDATE_MFA_METHOD_WITH_NO_CHANGE,
                        204,
                        Optional.empty()),
                Arguments.of(
                        MfaUpdateFailureReason.UNEXPECTED_ERROR,
                        500,
                        Optional.of(ErrorResponse.UNEXPECTED_ACCT_MGMT_ERROR)),
                Arguments.of(
                        MfaUpdateFailureReason.ATTEMPT_TO_UPDATE_PHONE_NUMBER_WITH_BACKUP_NUMBER,
                        400,
                        Optional.of(ErrorResponse.CANNOT_UPDATE_PRIMARY_SMS_TO_BACKUP_NUMBER)),
                Arguments.of(
                        MfaUpdateFailureReason.CANNOT_CHANGE_PRIORITY_OF_DEFAULT_METHOD,
                        400,
                        Optional.of(ErrorResponse.CANNOT_CHANGE_DEFAULT_MFA_PRIORITY)),
                Arguments.of(
                        MfaUpdateFailureReason.UNKOWN_MFA_IDENTIFIER,
                        404,
                        Optional.of(ErrorResponse.MFA_METHOD_NOT_FOUND)),
                Arguments.of(
                        MfaUpdateFailureReason.INVALID_PHONE_NUMBER,
                        400,
                        Optional.of(ErrorResponse.INVALID_PHONE_NUMBER)),
                Arguments.of(
                        MfaUpdateFailureReason.ATTEMPT_TO_UPDATE_BACKUP_WITH_NO_DEFAULT_METHOD,
                        500,
                        Optional.of(ErrorResponse.CANNOT_EDIT_BACKUP_MFA)));
    }

    @ParameterizedTest
    @MethodSource("updateFailureReasonsToExpectedResponses")
    void shouldReturnAppropriateResponseWhenMfaMethodsServiceReturnsError(
            MfaUpdateFailureReason failureReason,
            int expectedStatus,
            Optional<ErrorResponse> maybeErrorResponse) {
        setupValidOtpForEmail(TEST_OTP, EMAIL);
        var phoneNumber = UK_MOBILE_NUMBER;

        var event = requestWithPublicSubjectAndMfaIdentifier(TEST_PUBLIC_SUBJECT, MFA_IDENTIFIER);
        var eventWithUpdateRequest = event.withBody(updateSmsRequest(phoneNumber, TEST_OTP));
        var expectedDatabaseUpdateRequest =
                MfaMethodUpdateRequest.from(
                        PriorityIdentifier.DEFAULT, new RequestSmsMfaDetail(phoneNumber, TEST_OTP));
        when(mfaMethodsService.updateMfaMethod(
                        eq(EMAIL), any(), any(), eq(expectedDatabaseUpdateRequest)))
                .thenReturn(Result.failure(new MfaUpdateFailure(failureReason)));
        when(mfaMethodsService.getMfaMethod(EMAIL, MFA_IDENTIFIER))
                .thenReturn(
                        Result.success(
                                new MFAMethodsService.GetMfaResult(
                                        DEFAULT_SMS_METHOD, List.of(DEFAULT_SMS_METHOD))));
        var result = handler.handleRequest(eventWithUpdateRequest, context);

        assertThat(result, hasStatus(expectedStatus));
        maybeErrorResponse.ifPresent(
                expectedError -> assertThat(result, hasJsonBody(expectedError)));

        verify(sqsClient, never()).send(any());
        verify(auditService, never())
                .submitAuditEvent(
                        not(eq(AUTH_CODE_VERIFIED)), any(), any(AuditService.MetadataPair[].class));
    }

    @Test
    void shouldRaiseSwitchFailedAuditEvent() {
        setupValidOtpForEmail(TEST_OTP, EMAIL);
        var phoneNumber = BACKUP_SMS_METHOD.getDestination();
        var event = requestWithPublicSubjectAndMfaIdentifier(TEST_PUBLIC_SUBJECT, MFA_IDENTIFIER);
        var eventWithUpdateRequest = event.withBody(updateSmsRequest(phoneNumber, TEST_OTP));

        when(mfaMethodsService.getMfaMethod(EMAIL, MFA_IDENTIFIER))
                .thenReturn(
                        Result.success(
                                new MFAMethodsService.GetMfaResult(
                                        DEFAULT_SMS_METHOD, List.of(DEFAULT_SMS_METHOD))));
        var expectedDatabaseUpdateRequest =
                MfaMethodUpdateRequest.from(
                        PriorityIdentifier.DEFAULT, new RequestSmsMfaDetail(phoneNumber, TEST_OTP));
        when(mfaMethodsService.updateMfaMethod(
                        eq(EMAIL), any(), any(), eq(expectedDatabaseUpdateRequest)))
                .thenReturn(
                        Result.failure(
                                new MfaUpdateFailure(
                                        MfaUpdateFailureReason.UNEXPECTED_ERROR,
                                        MFAMethodUpdateIdentifier.SWITCHED_MFA_METHODS,
                                        BACKUP_SMS_METHOD)));

        handler.handleRequest(eventWithUpdateRequest, context);

        var expectedAuditContext =
                BASE_AUDIT_CONTEXT
                        .withPhoneNumber(UK_MOBILE_NUMBER)
                        .withMetadataItem(pair("mfa-type", BACKUP_SMS_METHOD.getMfaMethodType()))
                        .withMetadataItem(pair("mfa-method", BACKUP.name().toLowerCase()));

        verify(auditService)
                .submitAuditEvent(
                        AUTH_MFA_METHOD_SWITCH_FAILED,
                        expectedAuditContext,
                        AUDIT_EVENT_COMPONENT_ID_HOME);
    }

    @Test
    void shouldReturn500WhenConversionToMfaMethodResponseFails() {
        var credential = "some credential";

        when(mfaMethodsService.getMfaMethod(EMAIL, MFA_IDENTIFIER))
                .thenReturn(
                        Result.success(
                                new MFAMethodsService.GetMfaResult(
                                        DEFAULT_SMS_METHOD, List.of(DEFAULT_SMS_METHOD))));
        var mfaWithInvalidType =
                new MFAMethod("invalid method type", credential, true, true, "updatedString");
        when(mfaMethodsService.updateMfaMethod(eq(EMAIL), any(), any(), any()))
                .thenReturn(
                        Result.success(
                                new MFAMethodsService.MfaUpdateResponse(
                                        List.of(mfaWithInvalidType),
                                        MFAMethodUpdateIdentifier.CHANGED_DEFAULT_MFA)));

        var event = requestWithPublicSubjectAndMfaIdentifier(TEST_PUBLIC_SUBJECT, MFA_IDENTIFIER);
        var eventWithUpdateRequest = event.withBody(updateAuthAppRequest(credential));

        var result = handler.handleRequest(eventWithUpdateRequest, context);

        assertThat(result, hasStatus(500));
        assertThat(result, hasJsonBody(ErrorResponse.UNEXPECTED_ACCT_MGMT_ERROR));

        verify(sqsClient, never()).send(any());
        verify(auditService, never())
                .submitAuditEvent(
                        not(eq(AUTH_CODE_VERIFIED)), any(), any(AuditService.MetadataPair[].class));
    }

    @Test
    void shouldReturn400WhenJsonIsInvalid() {
        var event =
                requestWithPublicSubjectAndMfaIdentifier(TEST_PUBLIC_SUBJECT, MFA_IDENTIFIER)
                        .withBody("Invalid JSON");

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.REQUEST_MISSING_PARAMS));

        verify(sqsClient, never()).send(any());
        verifyNoInteractions(auditService);
    }

    @Test
    void shouldReturn400WhenPathParameterIsEmpty() {
        var event =
                baseRequestWithoutPathParams(TEST_INTERNAL_SUBJECT)
                        .withPathParameters(
                                Map.of(
                                        "mfaIdentifier",
                                        "some-mfa-identifier",
                                        "publicSubjectId",
                                        ""));

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.REQUEST_MISSING_PARAMS));

        verify(sqsClient, never()).send(any());
        verifyNoInteractions(auditService);
    }

    @Test
    void shouldReturn400WhenMfaIdentifierParameterIsEmpty() {
        var event =
                baseRequestWithoutPathParams(TEST_INTERNAL_SUBJECT)
                        .withPathParameters(
                                Map.of(
                                        "publicSubjectId",
                                        "some-public-subject-id",
                                        "mfaIdentifier",
                                        ""));

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.REQUEST_MISSING_PARAMS));

        verify(sqsClient, never()).send(any());
        verifyNoInteractions(auditService);
    }

    @Test
    void shouldReturn400WhenPublicSubjectIdParameterIsNull() {
        var pathParams = new HashMap<String, String>();
        pathParams.put("publicSubjectId", null);
        pathParams.put("mfaIdentifier", MFA_IDENTIFIER);
        var event =
                baseRequestWithoutPathParams(TEST_INTERNAL_SUBJECT).withPathParameters(pathParams);

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.REQUEST_MISSING_PARAMS));

        verify(sqsClient, never()).send(any());
        verifyNoInteractions(auditService);
    }

    @Test
    void shouldReturn400WhenMfaIdentifierParameterIsNull() {
        var pathParams = new HashMap<String, String>();
        pathParams.put("publicSubjectId", TEST_PUBLIC_SUBJECT);
        pathParams.put("mfaIdentifier", null);
        var event =
                baseRequestWithoutPathParams(TEST_INTERNAL_SUBJECT).withPathParameters(pathParams);

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.REQUEST_MISSING_PARAMS));

        verify(sqsClient, never()).send(any());
        verifyNoInteractions(auditService);
    }

    @Test
    void shouldReturn400WhenPhoneNumberIsInvalidFormat() {
        var invalidPhoneNumber = "+44123"; // Invalid UK number format
        var event = requestWithPublicSubjectAndMfaIdentifier(TEST_PUBLIC_SUBJECT, MFA_IDENTIFIER);
        event = event.withBody(updateSmsRequest(invalidPhoneNumber, TEST_OTP));

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.INVALID_PHONE_NUMBER));

        verify(sqsClient, never()).send(any());
        verifyNoInteractions(auditService);
    }

    private static Stream<Arguments> invalidRequestBodies() {
        return Stream.of(
                // Invalid priority identifier
                Arguments.of(
                        "Priority identifier is null",
                        """
                {
                  "mfaMethod": {
                    "priorityIdentifier": null,
                    "method": {
                        "mfaMethodType": "SMS",
                        "phoneNumber": "123456789",
                        "otp": "123456"
                    }
                  }
                }
                """),
                Arguments.of(
                        "Priority identifier is invalid",
                        """
                {
                  "mfaMethod": {
                    "priorityIdentifier": "INVALID",
                    "method": {
                        "mfaMethodType": "SMS",
                        "phoneNumber": "123456789",
                        "otp": "123456"
                    }
                  }
                }
                """),
                // SMS validation
                Arguments.of(
                        "SMS request has empty phone number",
                        """
                {
                  "mfaMethod": {
                    "priorityIdentifier": "DEFAULT",
                    "method": {
                        "mfaMethodType": "SMS",
                        "phoneNumber": "",
                        "otp": "123456"
                    }
                  }
                }
                """),
                Arguments.of(
                        "SMS request has empty OTP",
                        """
                {
                  "mfaMethod": {
                    "priorityIdentifier": "DEFAULT",
                    "method": {
                        "mfaMethodType": "SMS",
                        "phoneNumber": "123456789",
                        "otp": ""
                    }
                  }
                }
                """),
                Arguments.of(
                        "SMS request has whitespace-only phone number",
                        """
                {
                  "mfaMethod": {
                    "priorityIdentifier": "DEFAULT",
                    "method": {
                        "mfaMethodType": "SMS",
                        "phoneNumber": "   ",
                        "otp": "123456"
                    }
                  }
                }
                """),
                Arguments.of(
                        "SMS request has whitespace-only OTP",
                        """
                {
                  "mfaMethod": {
                    "priorityIdentifier": "DEFAULT",
                    "method": {
                        "mfaMethodType": "SMS",
                        "phoneNumber": "123456789",
                        "otp": "   "
                    }
                  }
                }
                """),
                // Auth app validation
                Arguments.of(
                        "Auth app request has empty credential",
                        """
                {
                  "mfaMethod": {
                    "priorityIdentifier": "DEFAULT",
                    "method": {
                        "mfaMethodType": "AUTH_APP",
                        "credential": ""
                    }
                  }
                }
                """),
                Arguments.of(
                        "Auth app request has whitespace-only credential",
                        """
                {
                  "mfaMethod": {
                    "priorityIdentifier": "DEFAULT",
                    "method": {
                        "mfaMethodType": "AUTH_APP",
                        "credential": "   "
                    }
                  }
                }
                """));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("invalidRequestBodies")
    void shouldReturn400WhenRequestBodyIsInvalid(String testName, String requestBody) {
        var event =
                requestWithPublicSubjectAndMfaIdentifier(TEST_PUBLIC_SUBJECT, MFA_IDENTIFIER)
                        .withBody(requestBody);

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.REQUEST_MISSING_PARAMS));

        verify(sqsClient, never()).send(any());
        verifyNoInteractions(auditService);
    }

    @Test
    void shouldReturn200WhenValidRequestWithNullMethodForSwitching() {
        var requestBody =
                """
                        {
                          "mfaMethod": {
                            "priorityIdentifier": "DEFAULT",
                            "method": null
                          }
                        }
                        """;
        var event =
                requestWithPublicSubjectAndMfaIdentifier(TEST_PUBLIC_SUBJECT, MFA_IDENTIFIER)
                        .withBody(requestBody);

        when(mfaMethodsService.getMfaMethod(EMAIL, MFA_IDENTIFIER))
                .thenReturn(
                        Result.success(
                                new MFAMethodsService.GetMfaResult(
                                        DEFAULT_SMS_METHOD, List.of(DEFAULT_SMS_METHOD))));
        var switchedMfaMethod =
                MFAMethod.authAppMfaMethod(
                        "test-credential", true, true, PriorityIdentifier.DEFAULT, MFA_IDENTIFIER);
        when(mfaMethodsService.updateMfaMethod(any(), any(), any(), any()))
                .thenReturn(
                        Result.success(
                                new MFAMethodsService.MfaUpdateResponse(
                                        List.of(switchedMfaMethod),
                                        MFAMethodUpdateIdentifier.SWITCHED_MFA_METHODS)));

        var result = handler.handleRequest(event, context);

        assertEquals(200, result.getStatusCode());

        verify(authenticationService).getOptionalUserProfileFromPublicSubject(TEST_PUBLIC_SUBJECT);
        verify(mfaMethodsService)
                .updateMfaMethod(
                        eq(EMAIL), eq(DEFAULT_SMS_METHOD), eq(List.of(DEFAULT_SMS_METHOD)), any());
        verify(sqsClient).send(any());
    }

    @Test
    void shouldReturn400WhenFeatureFlagDisabled() {
        when(configurationService.isMfaMethodManagementApiEnabled()).thenReturn(false);

        var event = requestWithPublicSubjectAndMfaIdentifier(TEST_PUBLIC_SUBJECT, MFA_IDENTIFIER);

        var result = handler.handleRequest(event, context);
        assertEquals(400, result.getStatusCode());

        verify(sqsClient, never()).send(any());
        verifyNoInteractions(auditService);
    }

    @Test
    void shouldReturn400WhenInternationalNumberAndFeatureFlagDisabled() throws Json.JsonException {
        when(configurationService.isAccountManagementInternationalSmsEnabled()).thenReturn(false);

        var event = requestWithPublicSubjectAndMfaIdentifier(TEST_PUBLIC_SUBJECT, MFA_IDENTIFIER);
        var eventWithUpdateRequest =
                event.withBody(updateSmsRequest(INTERNATIONAL_MOBILE_NUMBER, TEST_OTP));

        setupValidOtpForEmail(TEST_OTP, EMAIL);
        when(mfaMethodsService.getMfaMethod(EMAIL, MFA_IDENTIFIER))
                .thenReturn(
                        Result.success(
                                new MFAMethodsService.GetMfaResult(
                                        DEFAULT_SMS_METHOD, List.of(DEFAULT_SMS_METHOD))));

        var result = handler.handleRequest(eventWithUpdateRequest, context);

        assertEquals(400, result.getStatusCode());
        assertThat(result, hasJsonBody(ErrorResponse.INTERNATIONAL_PHONE_NUMBER_NOT_SUPPORTED));
    }

    @Test
    void shouldReturn401WhenPrincipalIsInvalid() {
        var event =
                requestWithPublicSubjectMfaIdentifierAndPrincipal(
                        TEST_PUBLIC_SUBJECT, MFA_IDENTIFIER, "invalid-principal");
        event = event.withBody(updateSmsRequest(UK_MOBILE_NUMBER, TEST_OTP));
        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(401));
        assertThat(result, hasJsonBody(ErrorResponse.INVALID_PRINCIPAL));

        verify(sqsClient, never()).send(any());
        verifyNoInteractions(auditService);
    }

    @Test
    void shouldReturn404WhenUserProfileIsNotFoundForPublicSubject() {
        when(authenticationService.getOptionalUserProfileFromPublicSubject(TEST_PUBLIC_SUBJECT))
                .thenReturn(Optional.empty());

        var event = requestWithPublicSubjectAndMfaIdentifier(TEST_PUBLIC_SUBJECT, MFA_IDENTIFIER);
        event = event.withBody(updateSmsRequest(UK_MOBILE_NUMBER, TEST_OTP));
        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(404));
        assertThat(result, hasJsonBody(ErrorResponse.USER_NOT_FOUND));

        verify(sqsClient, never()).send(any());
        verifyNoInteractions(auditService);
    }

    @Test
    void shouldReturnClientErrorWhenOTPInvalid() {
        when(codeStorageService.isValidOtpCode(
                        EMAIL, TEST_OTP, NotificationType.VERIFY_PHONE_NUMBER))
                .thenReturn(false);
        when(configurationService.getInternalSectorUri()).thenReturn("https://test.account.gov.uk");
        when(mfaMethodsService.getMfaMethod(EMAIL, MFA_IDENTIFIER))
                .thenReturn(
                        Result.success(
                                new MFAMethodsService.GetMfaResult(
                                        DEFAULT_SMS_METHOD, List.of(DEFAULT_SMS_METHOD))));

        var phoneNumber = UK_MOBILE_NUMBER;

        var event = requestWithPublicSubjectAndMfaIdentifier(TEST_PUBLIC_SUBJECT, MFA_IDENTIFIER);
        var eventWithUpdateRequest = event.withBody(updateSmsRequest(phoneNumber, TEST_OTP));
        var result = handler.handleRequest(eventWithUpdateRequest, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.INVALID_OTP));

        var expectedAuditContext =
                BASE_AUDIT_CONTEXT
                        .withPhoneNumber(phoneNumber)
                        .withMetadataItem(pair("mfa-type", "SMS"))
                        .withMetadataItem(pair("mfa-method", DEFAULT.name().toLowerCase()));

        verify(auditService)
                .submitAuditEvent(
                        AUTH_INVALID_CODE_SENT,
                        expectedAuditContext,
                        AUDIT_EVENT_COMPONENT_ID_HOME);

        verify(sqsClient, never()).send(any());
    }

    @Test
    void shouldEmitAuthUpdateProfileAuthAppAuditEventWhenUpdatingAuthApp() {
        when(mfaMethodsService.getMfaMethod(EMAIL, MFA_IDENTIFIER))
                .thenReturn(
                        Result.success(
                                new MFAMethodsService.GetMfaResult(
                                        DEFAULT_SMS_METHOD, List.of(DEFAULT_SMS_METHOD))));

        var credential = "some-credential";
        var event = requestWithPublicSubjectAndMfaIdentifier(TEST_PUBLIC_SUBJECT, MFA_IDENTIFIER);
        var eventWithUpdateRequest = event.withBody(updateAuthAppRequest(credential));

        var expectedDatabaseUpdateRequest =
                MfaMethodUpdateRequest.from(
                        PriorityIdentifier.DEFAULT, new RequestAuthAppMfaDetail(credential));
        var updatedMfaMethod =
                MFAMethod.authAppMfaMethod(
                        credential, true, true, PriorityIdentifier.DEFAULT, MFA_IDENTIFIER);
        when(mfaMethodsService.updateMfaMethod(
                        eq(EMAIL), any(), any(), eq(expectedDatabaseUpdateRequest)))
                .thenReturn(
                        Result.success(
                                new MFAMethodsService.MfaUpdateResponse(
                                        List.of(updatedMfaMethod),
                                        MFAMethodUpdateIdentifier.CHANGED_AUTHENTICATOR_APP)));

        var result = handler.handleRequest(eventWithUpdateRequest, context);

        assertEquals(200, result.getStatusCode());

        var expectedContext =
                BASE_AUDIT_CONTEXT
                        .withPhoneNumber(null)
                        .withMetadataItem(pair("mfa-type", "AUTH_APP"))
                        .withMetadataItem(pair("mfa-method", DEFAULT.name().toLowerCase()))
                        .withMetadataItem(pair("journey-type", ACCOUNT_MANAGEMENT.getValue()));
        // Journey type duplicated here - in base context

        verify(auditService)
                .submitAuditEvent(
                        AUTH_UPDATE_PROFILE_AUTH_APP,
                        expectedContext,
                        AUDIT_EVENT_COMPONENT_ID_HOME);
    }

    private static APIGatewayProxyRequestEvent baseRequestWithoutPathParams(String principal) {
        APIGatewayProxyRequestEvent.ProxyRequestContext proxyRequestContext =
                new APIGatewayProxyRequestEvent.ProxyRequestContext();
        Map<String, Object> authorizerParams = new HashMap<>();
        authorizerParams.put("principalId", principal);
        authorizerParams.put("clientId", TEST_CLIENT);
        proxyRequestContext.setAuthorizer(authorizerParams);
        proxyRequestContext.setIdentity(identityWithSourceIp(IP_ADDRESS));

        return new APIGatewayProxyRequestEvent()
                .withHeaders(VALID_HEADERS)
                .withRequestContext(proxyRequestContext);
    }

    private static APIGatewayProxyRequestEvent requestWithPublicSubjectMfaIdentifierAndPrincipal(
            String publicSubject, String mfaIdentifier, String principal) {
        return baseRequestWithoutPathParams(principal)
                .withPathParameters(
                        Map.ofEntries(
                                Map.entry("publicSubjectId", publicSubject),
                                Map.entry("mfaIdentifier", mfaIdentifier)));
    }

    private static APIGatewayProxyRequestEvent requestWithPublicSubjectAndMfaIdentifier(
            String publicSubject, String mfaIdentifier) {
        return requestWithPublicSubjectMfaIdentifierAndPrincipal(
                publicSubject, mfaIdentifier, TEST_INTERNAL_SUBJECT);
    }

    private String updateSmsRequest(String phoneNumber, String otp) {
        return format(
                """
                        {
                          "mfaMethod": {
                            "priorityIdentifier": "DEFAULT",
                            "method": {
                                "mfaMethodType": "SMS",
                                "phoneNumber": "%s",
                                "otp": "%s"
                            }
                          }
                        }
                        """,
                phoneNumber, otp);
    }

    private String updateAuthAppRequest(String credential) {
        return format(
                """
                        {
                          "mfaMethod": {
                            "priorityIdentifier": "DEFAULT",
                            "method": {
                                "mfaMethodType": "AUTH_APP",
                                "credential": "%s"
                            }
                          }
                        }
                        """,
                credential);
    }

    private static void setupValidOtpForEmail(String otp, String email) {
        when(codeStorageService.isValidOtpCode(email, otp, NotificationType.VERIFY_PHONE_NUMBER))
                .thenReturn(true);
    }
}
