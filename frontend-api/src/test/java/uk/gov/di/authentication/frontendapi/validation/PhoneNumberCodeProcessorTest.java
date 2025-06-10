package uk.gov.di.authentication.frontendapi.validation;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.entity.CodeRequest;
import uk.gov.di.authentication.entity.VerifyMfaCodeRequest;
import uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent;
import uk.gov.di.authentication.frontendapi.entity.PhoneNumberRequest;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.CodeRequestType;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.NotificationType;
import uk.gov.di.authentication.shared.entity.PriorityIdentifier;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethod;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.helpers.CommonTestVariables;
import uk.gov.di.authentication.shared.helpers.IdGenerator;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.AwsSqsClient;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoAccountModifiersService;
import uk.gov.di.authentication.shared.services.SerializationService;
import uk.gov.di.authentication.shared.services.mfa.MFAMethodsService;
import uk.gov.di.authentication.shared.state.UserContext;

import java.util.Optional;
import java.util.UUID;
import java.util.stream.Stream;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.CLIENT_ID;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.EMAIL;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.UK_NOTIFY_MOBILE_TEST_NUMBER;
import static uk.gov.di.authentication.shared.services.AuditService.MetadataPair.pair;
import static uk.gov.di.authentication.shared.services.CodeStorageService.CODE_BLOCKED_KEY_PREFIX;

class PhoneNumberCodeProcessorTest {

    private PhoneNumberCodeProcessor phoneNumberCodeProcessor;
    private final AuthSessionItem authSession =
            new AuthSessionItem()
                    .withSessionId(SESSION_ID)
                    .withEmailAddress(EMAIL)
                    .withInternalCommonSubjectId(INTERNAL_SUB_ID)
                    .withClientId(CLIENT_ID);
    private final CodeStorageService codeStorageService = mock(CodeStorageService.class);
    private final UserContext userContext = mock(UserContext.class);
    private final UserProfile userProfile = mock(UserProfile.class);
    private final ClientRegistry clientRegistry = mock(ClientRegistry.class);
    private final AuditService auditService = mock(AuditService.class);
    private final AuthenticationService authenticationService = mock(AuthenticationService.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final MFAMethodsService mfaMethodsService = mock(MFAMethodsService.class);
    private final AwsSqsClient sqsClient = mock(AwsSqsClient.class);
    private final DynamoAccountModifiersService accountModifiersService =
            mock(DynamoAccountModifiersService.class);
    private static final String VALID_CODE = "123456";
    private static final String INVALID_CODE = "826272";
    private static final String PERSISTENT_ID = "some-persistent-session-id";
    private static final String CLIENT_SESSION_ID = "a-client-session-id";
    private static final String SESSION_ID = "a-session-id";
    private static final String IP_ADDRESS = "123.123.123.123";
    private static final String INTERNAL_SUB_ID = "urn:fdc:gov.uk:2022:" + IdGenerator.generate();
    private static final String TXMA_ENCODED_HEADER_VALUE = "txma-test-value";
    private static final AuditContext AUDIT_CONTEXT =
            new AuditContext(
                    CLIENT_ID,
                    CLIENT_SESSION_ID,
                    SESSION_ID,
                    INTERNAL_SUB_ID,
                    CommonTestVariables.EMAIL,
                    IP_ADDRESS,
                    CommonTestVariables.UK_MOBILE_NUMBER,
                    PERSISTENT_ID,
                    Optional.of(TXMA_ENCODED_HEADER_VALUE));

    @BeforeEach
    void setup() {
        when(configurationService.getCodeMaxRetries()).thenReturn(3);
        when(userContext.getTxmaAuditEncoded()).thenReturn(TXMA_ENCODED_HEADER_VALUE);
    }

    @ParameterizedTest
    @MethodSource("codeRequestTypes")
    void shouldReturnNoErrorForValidPhoneNumberCode(
            CodeRequestType codeRequestType, JourneyType journeyType) {
        setupPhoneNumberCode(
                new VerifyMfaCodeRequest(
                        MFAMethodType.SMS,
                        VALID_CODE,
                        journeyType,
                        CommonTestVariables.UK_MOBILE_NUMBER),
                codeRequestType);

        assertThat(phoneNumberCodeProcessor.validateCode(), equalTo(Optional.empty()));
    }

    @ParameterizedTest
    @MethodSource("codeRequestTypes")
    void shouldDeleteMfaCodeFromDataStoreWhenValidRegistrationPhoneNumberCode(
            CodeRequestType codeRequestType,
            JourneyType journeyType,
            NotificationType notificationType) {
        setupPhoneNumberCode(
                new VerifyMfaCodeRequest(
                        MFAMethodType.SMS,
                        VALID_CODE,
                        journeyType,
                        CommonTestVariables.UK_MOBILE_NUMBER),
                codeRequestType);

        phoneNumberCodeProcessor.validateCode();
        verify(codeStorageService)
                .deleteOtpCode(
                        CommonTestVariables.EMAIL.concat(CommonTestVariables.UK_MOBILE_NUMBER),
                        notificationType);
    }

    @Test
    void shouldReturnErrorForInvalidRegistrationPhoneNumberCode() {
        setupPhoneNumberCode(
                new VerifyMfaCodeRequest(
                        MFAMethodType.SMS,
                        INVALID_CODE,
                        JourneyType.REGISTRATION,
                        CommonTestVariables.UK_MOBILE_NUMBER),
                CodeRequestType.SMS_REGISTRATION);

        assertThat(
                phoneNumberCodeProcessor.validateCode(),
                equalTo(Optional.of(ErrorResponse.ERROR_1037)));
    }

    @Test
    void shouldReturnErrorForInvalidMfaPhoneNumberCode() {
        setupPhoneNumberCode(
                new VerifyMfaCodeRequest(
                        MFAMethodType.SMS,
                        INVALID_CODE,
                        JourneyType.PASSWORD_RESET_MFA,
                        CommonTestVariables.UK_MOBILE_NUMBER),
                CodeRequestType.PW_RESET_MFA_SMS);

        assertThat(
                phoneNumberCodeProcessor.validateCode(),
                equalTo(Optional.of(ErrorResponse.ERROR_1035)));
    }

    @ParameterizedTest
    @MethodSource("codeRequestTypes")
    void shouldNotDeleteMfaCodeFromDataStoreWhenInvalidRegistrationPhoneNumberCode(
            CodeRequestType codeRequestType,
            JourneyType journeyType,
            NotificationType notificationType) {
        setupPhoneNumberCode(
                new VerifyMfaCodeRequest(
                        MFAMethodType.SMS,
                        INVALID_CODE,
                        journeyType,
                        CommonTestVariables.UK_MOBILE_NUMBER),
                codeRequestType);

        phoneNumberCodeProcessor.validateCode();
        verify(codeStorageService, never())
                .deleteOtpCode(
                        CommonTestVariables.EMAIL.concat(CommonTestVariables.UK_MOBILE_NUMBER),
                        notificationType);
    }

    @Test
    void shouldReturnErrorWhenInvalidRegistrationPhoneNumberCodeUsedTooManyTimes() {
        setUpPhoneNumberCodeRetryLimitExceeded(
                new VerifyMfaCodeRequest(
                        MFAMethodType.SMS,
                        INVALID_CODE,
                        JourneyType.REGISTRATION,
                        CommonTestVariables.UK_MOBILE_NUMBER));

        assertThat(
                phoneNumberCodeProcessor.validateCode(),
                equalTo(Optional.of(ErrorResponse.ERROR_1034)));
    }

    @Test
    void shouldReturnErrorWhenInvalidMfaPhoneNumberCodeUsedTooManyTimes() {
        setUpPhoneNumberCodeRetryLimitExceeded(
                new VerifyMfaCodeRequest(
                        MFAMethodType.SMS,
                        INVALID_CODE,
                        JourneyType.PASSWORD_RESET_MFA,
                        CommonTestVariables.UK_MOBILE_NUMBER));

        assertThat(
                phoneNumberCodeProcessor.validateCode(),
                equalTo(Optional.of(ErrorResponse.ERROR_1027)));
    }

    @Test
    void shouldReturnErrorWhenInvalidReauthenticateMfaPhoneNumberCodeUsedTooManyTimes() {
        setUpPhoneNumberCodeRetryLimitExceeded(
                new VerifyMfaCodeRequest(
                        MFAMethodType.SMS,
                        INVALID_CODE,
                        JourneyType.REAUTHENTICATION,
                        CommonTestVariables.UK_MOBILE_NUMBER));

        assertThat(
                phoneNumberCodeProcessor.validateCode(),
                equalTo(Optional.of(ErrorResponse.ERROR_1035)));
    }

    @ParameterizedTest
    @MethodSource("codeRequestTypes")
    void shouldReturnErrorWhenUserIsBlockedFromEnteringRegistrationPhoneNumberCodes(
            CodeRequestType codeRequestType, JourneyType journeyType) {
        setUpBlockedPhoneNumberCode(
                new VerifyMfaCodeRequest(
                        MFAMethodType.SMS,
                        INVALID_CODE,
                        journeyType,
                        CommonTestVariables.UK_MOBILE_NUMBER),
                codeRequestType);

        assertThat(
                phoneNumberCodeProcessor.validateCode(),
                equalTo(Optional.of(ErrorResponse.ERROR_1034)));
    }

    @Test
    void shouldThrowExceptionForSignInPhoneNumberCode() {
        setupPhoneNumberCode(
                new VerifyMfaCodeRequest(
                        MFAMethodType.SMS,
                        INVALID_CODE,
                        JourneyType.SIGN_IN,
                        CommonTestVariables.UK_MOBILE_NUMBER),
                CodeRequestType.SMS_SIGN_IN);

        var expectedException =
                assertThrows(
                        RuntimeException.class,
                        () -> phoneNumberCodeProcessor.validateCode(),
                        "Expected to throw exception");

        assertThat(
                expectedException.getMessage(),
                equalTo("Sign In Phone number codes are not supported"));
    }

    @Test
    void shouldUpdateDynamoAndCreateAuditEventWhenRegistration() {
        setupPhoneNumberCode(
                new VerifyMfaCodeRequest(
                        MFAMethodType.SMS,
                        VALID_CODE,
                        JourneyType.REGISTRATION,
                        CommonTestVariables.UK_MOBILE_NUMBER),
                CodeRequestType.SMS_REGISTRATION);

        phoneNumberCodeProcessor.processSuccessfulCodeRequest(
                IP_ADDRESS, PERSISTENT_ID, userProfile);

        verify(authenticationService)
                .updatePhoneNumberAndAccountVerifiedStatus(
                        CommonTestVariables.EMAIL,
                        CommonTestVariables.UK_MOBILE_NUMBER,
                        true,
                        true);
        verify(authenticationService, never())
                .setVerifiedPhoneNumberAndRemoveAuthAppIfPresent(anyString(), anyString());
        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.AUTH_UPDATE_PROFILE_PHONE_NUMBER,
                        AUDIT_CONTEXT,
                        pair("mfa-type", MFAMethodType.SMS.getValue()),
                        pair("account-recovery", false));
    }

    @Test
    void shouldCallDynamoToUpdateMfaMethodAndCreateAuditEventWhenAccountRecovery() {
        when(userProfile.isMfaMethodsMigrated()).thenReturn(false);

        setupPhoneNumberCode(
                new VerifyMfaCodeRequest(
                        MFAMethodType.SMS,
                        VALID_CODE,
                        JourneyType.ACCOUNT_RECOVERY,
                        CommonTestVariables.UK_MOBILE_NUMBER),
                CodeRequestType.SMS_ACCOUNT_RECOVERY);

        phoneNumberCodeProcessor.processSuccessfulCodeRequest(
                IP_ADDRESS, PERSISTENT_ID, userProfile);

        verify(authenticationService)
                .setVerifiedPhoneNumberAndRemoveAuthAppIfPresent(
                        CommonTestVariables.EMAIL, CommonTestVariables.UK_MOBILE_NUMBER);
        verify(authenticationService, never())
                .updatePhoneNumberAndAccountVerifiedStatus(
                        anyString(), anyString(), anyBoolean(), anyBoolean());
        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.AUTH_UPDATE_PROFILE_PHONE_NUMBER,
                        AUDIT_CONTEXT,
                        pair("mfa-type", MFAMethodType.SMS.getValue()),
                        pair("account-recovery", true));
    }

    @Test
    void shouldNotUpdateDynamoOrCreateAuditEventWhenSignIn() {
        setupPhoneNumberCode(
                new VerifyMfaCodeRequest(
                        MFAMethodType.SMS,
                        VALID_CODE,
                        JourneyType.SIGN_IN,
                        CommonTestVariables.UK_MOBILE_NUMBER),
                CodeRequestType.SMS_REGISTRATION);

        phoneNumberCodeProcessor.processSuccessfulCodeRequest(
                IP_ADDRESS, PERSISTENT_ID, userProfile);

        verifyNoInteractions(authenticationService);
        verifyNoInteractions(auditService);
    }

    @ParameterizedTest
    @EnumSource(names = {"REGISTRATION", "ACCOUNT_RECOVERY"})
    void shouldSendPhoneNumberRequestToSqsClientIfFeatureSwitchIsOn(JourneyType journeyType) {
        when(configurationService.isPhoneCheckerWithReplyEnabled()).thenReturn(true);
        setupPhoneNumberCode(
                new VerifyMfaCodeRequest(
                        MFAMethodType.SMS,
                        VALID_CODE,
                        journeyType,
                        CommonTestVariables.UK_MOBILE_NUMBER),
                CodeRequestType.SMS_REGISTRATION);

        phoneNumberCodeProcessor.processSuccessfulCodeRequest(
                IP_ADDRESS, PERSISTENT_ID, userProfile);

        verify(sqsClient)
                .send(
                        SerializationService.getInstance()
                                .writeValueAsString(
                                        new PhoneNumberRequest(
                                                true,
                                                CommonTestVariables.UK_MOBILE_NUMBER,
                                                true,
                                                journeyType,
                                                INTERNAL_SUB_ID)));
    }

    @Test
    void
            shouldNotSendPhoneNumberRequestToSqsClientIfFeatureSwitchIsOnDuringAccountRecoveryUsingSamePhoneNumber() {
        when(configurationService.isPhoneCheckerWithReplyEnabled()).thenReturn(true);
        setupPhoneNumberCode(
                new VerifyMfaCodeRequest(
                        MFAMethodType.SMS,
                        VALID_CODE,
                        JourneyType.ACCOUNT_RECOVERY,
                        CommonTestVariables.UK_MOBILE_NUMBER),
                CodeRequestType.SMS_ACCOUNT_RECOVERY);
        when(userProfile.getPhoneNumber()).thenReturn(CommonTestVariables.UK_MOBILE_NUMBER);

        phoneNumberCodeProcessor.processSuccessfulCodeRequest(
                IP_ADDRESS, PERSISTENT_ID, userProfile);

        verifyNoInteractions(sqsClient);
    }

    @Test
    void shouldNotSendPhoneNumberRequestToSqsClientIfFeatureSwitchIsOff() {
        when(configurationService.isPhoneCheckerWithReplyEnabled()).thenReturn(false);
        setupPhoneNumberCode(
                new VerifyMfaCodeRequest(
                        MFAMethodType.SMS,
                        VALID_CODE,
                        JourneyType.REGISTRATION,
                        CommonTestVariables.UK_MOBILE_NUMBER),
                CodeRequestType.SMS_REGISTRATION);

        phoneNumberCodeProcessor.processSuccessfulCodeRequest(
                IP_ADDRESS, PERSISTENT_ID, userProfile);

        verifyNoInteractions(sqsClient);
    }

    @ParameterizedTest
    @EnumSource(names = {"REGISTRATION", "ACCOUNT_RECOVERY"})
    void shouldNotSendPhoneNumberRequestToSqsClientIfTestClientAndTestUser(
            JourneyType journeyType) {
        when(configurationService.isPhoneCheckerWithReplyEnabled()).thenReturn(true);
        setupPhoneNumberCode(
                new VerifyMfaCodeRequest(
                        MFAMethodType.SMS, VALID_CODE, journeyType, UK_NOTIFY_MOBILE_TEST_NUMBER),
                CodeRequestType.SMS_REGISTRATION);
        authSession.setIsSmokeTest(true);
        when(userContext.getClient()).thenReturn(Optional.of(clientRegistry));

        phoneNumberCodeProcessor.processSuccessfulCodeRequest(
                IP_ADDRESS, PERSISTENT_ID, userProfile);

        verifyNoInteractions(sqsClient);
    }

    @Test
    void shouldResetMigratedUsersMfaMethod() {
        when(userProfile.isMfaMethodsMigrated()).thenReturn(true);
        when(userProfile.getEmail()).thenReturn(EMAIL);

        setupPhoneNumberCode(
                new VerifyMfaCodeRequest(
                        MFAMethodType.SMS,
                        VALID_CODE,
                        JourneyType.ACCOUNT_RECOVERY,
                        CommonTestVariables.UK_MOBILE_NUMBER),
                CodeRequestType.SMS_ACCOUNT_RECOVERY);

        phoneNumberCodeProcessor.processSuccessfulCodeRequest(
                IP_ADDRESS, PERSISTENT_ID, userProfile);

        ArgumentCaptor<MFAMethod> mfaMethodCaptor = ArgumentCaptor.forClass(MFAMethod.class);
        verify(mfaMethodsService)
                .deleteMigratedMFAsAndCreateNewDefault(eq(EMAIL), mfaMethodCaptor.capture());
        var capturedMfaMethod = mfaMethodCaptor.getValue();
        assertTrue(capturedMfaMethod.isMethodVerified());
        assertTrue(capturedMfaMethod.isEnabled());
        assertEquals(CommonTestVariables.UK_MOBILE_NUMBER, capturedMfaMethod.getDestination());
        assertEquals(PriorityIdentifier.DEFAULT.toString(), capturedMfaMethod.getPriority());
        assertInstanceOf(UUID.class, UUID.fromString(capturedMfaMethod.getMfaIdentifier()));
    }

    public void setupPhoneNumberCode(CodeRequest codeRequest, CodeRequestType codeRequestType) {
        var differentPhoneNumber = CommonTestVariables.UK_MOBILE_NUMBER.replace("789", "987");
        when(userContext.getClientSessionId()).thenReturn(CLIENT_SESSION_ID);
        when(userContext.getAuthSession()).thenReturn(authSession);
        when(userContext.getUserProfile()).thenReturn(Optional.of(userProfile));
        when(userProfile.isPhoneNumberVerified()).thenReturn(true);
        when(userProfile.getPhoneNumber()).thenReturn(differentPhoneNumber);
        when(configurationService.isTestClientsEnabled()).thenReturn(false);
        when(codeStorageService.getOtpCode(
                        CommonTestVariables.EMAIL.concat(codeRequest.getProfileInformation()),
                        NotificationType.VERIFY_PHONE_NUMBER))
                .thenReturn(Optional.of(VALID_CODE));
        when(codeStorageService.getOtpCode(
                        CommonTestVariables.EMAIL.concat(codeRequest.getProfileInformation()),
                        NotificationType.MFA_SMS))
                .thenReturn(Optional.of(VALID_CODE));
        when(codeStorageService.isBlockedForEmail(
                        CommonTestVariables.EMAIL, CODE_BLOCKED_KEY_PREFIX + codeRequestType))
                .thenReturn(false);
        phoneNumberCodeProcessor =
                new PhoneNumberCodeProcessor(
                        codeStorageService,
                        userContext,
                        configurationService,
                        codeRequest,
                        authenticationService,
                        auditService,
                        accountModifiersService,
                        sqsClient,
                        mfaMethodsService);
    }

    public void setUpPhoneNumberCodeRetryLimitExceeded(CodeRequest codeRequest) {
        when(codeStorageService.getIncorrectMfaCodeAttemptsCount(CommonTestVariables.EMAIL))
                .thenReturn(6);
        when(userContext.getAuthSession()).thenReturn(authSession);
        when(configurationService.isTestClientsEnabled()).thenReturn(false);
        when(codeStorageService.getOtpCode(
                        CommonTestVariables.EMAIL.concat(codeRequest.getProfileInformation()),
                        NotificationType.VERIFY_PHONE_NUMBER))
                .thenReturn(Optional.of(VALID_CODE));
        when(codeStorageService.isBlockedForEmail(
                        CommonTestVariables.EMAIL, CODE_BLOCKED_KEY_PREFIX))
                .thenReturn(false);
        phoneNumberCodeProcessor =
                new PhoneNumberCodeProcessor(
                        codeStorageService,
                        userContext,
                        configurationService,
                        codeRequest,
                        authenticationService,
                        auditService,
                        accountModifiersService,
                        sqsClient,
                        mfaMethodsService);
    }

    public void setUpBlockedPhoneNumberCode(
            CodeRequest codeRequest, CodeRequestType codeRequestType) {
        when(userContext.getAuthSession()).thenReturn(authSession);
        when(configurationService.isTestClientsEnabled()).thenReturn(false);
        when(codeStorageService.getOtpCode(
                        CommonTestVariables.EMAIL.concat(codeRequest.getProfileInformation()),
                        NotificationType.VERIFY_PHONE_NUMBER))
                .thenReturn(Optional.of(VALID_CODE));
        when(codeStorageService.isBlockedForEmail(
                        CommonTestVariables.EMAIL, CODE_BLOCKED_KEY_PREFIX + codeRequestType))
                .thenReturn(true);
        phoneNumberCodeProcessor =
                new PhoneNumberCodeProcessor(
                        codeStorageService,
                        userContext,
                        configurationService,
                        codeRequest,
                        authenticationService,
                        auditService,
                        accountModifiersService,
                        sqsClient,
                        mfaMethodsService);
    }

    private static Stream<Arguments> codeRequestTypes() {
        return Stream.of(
                Arguments.of(
                        CodeRequestType.PW_RESET_MFA_SMS,
                        JourneyType.PASSWORD_RESET_MFA,
                        NotificationType.MFA_SMS),
                Arguments.of(
                        CodeRequestType.SMS_REAUTHENTICATION,
                        JourneyType.REAUTHENTICATION,
                        NotificationType.MFA_SMS),
                Arguments.of(
                        CodeRequestType.SMS_REGISTRATION,
                        JourneyType.REGISTRATION,
                        NotificationType.VERIFY_PHONE_NUMBER));
    }
}
