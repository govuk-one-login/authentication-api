package uk.gov.di.authentication.frontendapi.validation;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.entity.CodeRequest;
import uk.gov.di.authentication.entity.VerifyMfaCodeRequest;
import uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent;
import uk.gov.di.authentication.shared.entity.CodeRequestType;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.MFAMethodType;
import uk.gov.di.authentication.shared.entity.NotificationType;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.helpers.IdGenerator;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoAccountModifiersService;
import uk.gov.di.authentication.shared.state.UserContext;

import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.shared.services.AuditService.MetadataPair.pair;
import static uk.gov.di.authentication.shared.services.CodeStorageService.CODE_BLOCKED_KEY_PREFIX;

class PhoneNumberCodeProcessorTest {

    private PhoneNumberCodeProcessor phoneNumberCodeProcessor;
    private final Session session = mock(Session.class);
    private final CodeStorageService codeStorageService = mock(CodeStorageService.class);
    private final UserContext userContext = mock(UserContext.class);
    private final AuditService auditService = mock(AuditService.class);
    private final AuthenticationService authenticationService = mock(AuthenticationService.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final DynamoAccountModifiersService accountModifiersService =
            mock(DynamoAccountModifiersService.class);
    private static final String TEST_EMAIL_ADDRESS = "joe.bloggs@example.com";
    private static final String VALID_CODE = "123456";
    private static final String INVALID_CODE = "826272";
    private static final String PHONE_NUMBER = "+447700900000";
    private static final String PERSISTENT_ID = "some-persistent-session-id";
    private static final String CLIENT_SESSION_ID = "a-client-session-id";
    private static final String SESSION_ID = "a-session-id";
    private static final String IP_ADDRESS = "123.123.123.123";
    private static final String INTERNAL_SUB_ID = "urn:fdc:gov.uk:2022:" + IdGenerator.generate();

    @BeforeEach
    void setup() {
        when(configurationService.getCodeMaxRetries()).thenReturn(5);
    }

    @Test
    void shouldReturnNoErrorForValidRegistrationPhoneNumberCode() {
        setupPhoneNumberCode(
                new VerifyMfaCodeRequest(
                        MFAMethodType.SMS, VALID_CODE, JourneyType.REGISTRATION, PHONE_NUMBER),
                CodeRequestType.SMS_REGISTRATION);

        assertThat(phoneNumberCodeProcessor.validateCode(), equalTo(Optional.empty()));
    }

    @Test
    void shouldDeleteMfaCodeFromDataStoreWhenValidRegistrationPhoneNumberCode() {
        setupPhoneNumberCode(
                new VerifyMfaCodeRequest(
                        MFAMethodType.SMS, VALID_CODE, JourneyType.REGISTRATION, PHONE_NUMBER),
                CodeRequestType.SMS_REGISTRATION);

        phoneNumberCodeProcessor.validateCode();
        verify(codeStorageService)
                .deleteOtpCode(TEST_EMAIL_ADDRESS, NotificationType.VERIFY_PHONE_NUMBER);
    }

    @Test
    void shouldReturnErrorForInvalidRegistrationPhoneNumberCode() {
        setupPhoneNumberCode(
                new VerifyMfaCodeRequest(
                        MFAMethodType.SMS, INVALID_CODE, JourneyType.REGISTRATION, PHONE_NUMBER),
                CodeRequestType.SMS_REGISTRATION);

        assertThat(
                phoneNumberCodeProcessor.validateCode(),
                equalTo(Optional.of(ErrorResponse.ERROR_1037)));
    }

    @Test
    void shouldNotDeleteMfaCodeFromDataStoreWhenInvalidRegistrationPhoneNumberCode() {
        setupPhoneNumberCode(
                new VerifyMfaCodeRequest(
                        MFAMethodType.SMS, INVALID_CODE, JourneyType.REGISTRATION, PHONE_NUMBER),
                CodeRequestType.SMS_REGISTRATION);

        phoneNumberCodeProcessor.validateCode();
        verify(codeStorageService, never())
                .deleteOtpCode(TEST_EMAIL_ADDRESS, NotificationType.VERIFY_PHONE_NUMBER);
    }

    @Test
    void shouldReturnErrorWhenInvalidRegistrationPhoneNumberCodeUsedTooManyTimes() {
        setUpPhoneNumberCodeRetryLimitExceeded(
                new VerifyMfaCodeRequest(
                        MFAMethodType.SMS, INVALID_CODE, JourneyType.REGISTRATION, PHONE_NUMBER));

        assertThat(
                phoneNumberCodeProcessor.validateCode(),
                equalTo(Optional.of(ErrorResponse.ERROR_1034)));
    }

    @Test
    void shouldReturnErrorWhenUserIsBlockedFromEnteringRegistrationPhoneNumberCodes() {
        setUpBlockedPhoneNumberCode(
                new VerifyMfaCodeRequest(
                        MFAMethodType.SMS, INVALID_CODE, JourneyType.REGISTRATION, PHONE_NUMBER),
                CodeRequestType.SMS_REGISTRATION);

        assertThat(
                phoneNumberCodeProcessor.validateCode(),
                equalTo(Optional.of(ErrorResponse.ERROR_1034)));
    }

    @Test
    void shouldThrowExceptionForSignInPhoneNumberCode() {
        setupPhoneNumberCode(
                new VerifyMfaCodeRequest(MFAMethodType.SMS, INVALID_CODE, JourneyType.SIGN_IN),
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
                        MFAMethodType.SMS, VALID_CODE, JourneyType.REGISTRATION, PHONE_NUMBER),
                CodeRequestType.SMS_REGISTRATION);

        phoneNumberCodeProcessor.processSuccessfulCodeRequest(IP_ADDRESS, PERSISTENT_ID);

        verify(authenticationService)
                .updatePhoneNumberAndAccountVerifiedStatus(
                        TEST_EMAIL_ADDRESS, PHONE_NUMBER, true, true);
        verify(authenticationService, never())
                .setVerifiedPhoneNumberAndRemoveAuthAppIfPresent(anyString(), anyString());
        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.UPDATE_PROFILE_PHONE_NUMBER,
                        CLIENT_SESSION_ID,
                        SESSION_ID,
                        AuditService.UNKNOWN,
                        INTERNAL_SUB_ID,
                        TEST_EMAIL_ADDRESS,
                        IP_ADDRESS,
                        PHONE_NUMBER,
                        PERSISTENT_ID,
                        pair("mfa-type", MFAMethodType.SMS.getValue()),
                        pair("account-recovery", false));
    }

    @Test
    void shouldCallDynamoToUpdateMfaMethodAndCreateAuditEventWhenAccountRecovery() {
        setupPhoneNumberCode(
                new VerifyMfaCodeRequest(
                        MFAMethodType.SMS, VALID_CODE, JourneyType.ACCOUNT_RECOVERY, PHONE_NUMBER),
                CodeRequestType.SMS_ACCOUNT_RECOVERY);

        phoneNumberCodeProcessor.processSuccessfulCodeRequest(IP_ADDRESS, PERSISTENT_ID);

        verify(authenticationService)
                .setVerifiedPhoneNumberAndRemoveAuthAppIfPresent(TEST_EMAIL_ADDRESS, PHONE_NUMBER);
        verify(authenticationService, never())
                .updatePhoneNumberAndAccountVerifiedStatus(
                        anyString(), anyString(), anyBoolean(), anyBoolean());
        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.UPDATE_PROFILE_PHONE_NUMBER,
                        CLIENT_SESSION_ID,
                        SESSION_ID,
                        AuditService.UNKNOWN,
                        INTERNAL_SUB_ID,
                        TEST_EMAIL_ADDRESS,
                        IP_ADDRESS,
                        PHONE_NUMBER,
                        PERSISTENT_ID,
                        pair("mfa-type", MFAMethodType.SMS.getValue()),
                        pair("account-recovery", true));
    }

    @Test
    void shouldNotUpdateDynamoOrCreateAuditEventWhenSignIn() {
        setupPhoneNumberCode(
                new VerifyMfaCodeRequest(MFAMethodType.SMS, VALID_CODE, JourneyType.SIGN_IN),
                CodeRequestType.SMS_REGISTRATION);

        phoneNumberCodeProcessor.processSuccessfulCodeRequest(IP_ADDRESS, PERSISTENT_ID);

        verifyNoInteractions(authenticationService);
        verifyNoInteractions(auditService);
    }

    public void setupPhoneNumberCode(CodeRequest codeRequest, CodeRequestType codeRequestType) {
        when(session.getEmailAddress()).thenReturn(TEST_EMAIL_ADDRESS);
        when(session.getSessionId()).thenReturn(SESSION_ID);
        when(session.getInternalCommonSubjectIdentifier()).thenReturn(INTERNAL_SUB_ID);
        when(userContext.getClientSessionId()).thenReturn(CLIENT_SESSION_ID);
        when(userContext.getSession()).thenReturn(session);
        when(configurationService.isTestClientsEnabled()).thenReturn(false);
        when(codeStorageService.getOtpCode(
                        TEST_EMAIL_ADDRESS, NotificationType.VERIFY_PHONE_NUMBER))
                .thenReturn(Optional.of(VALID_CODE));
        when(codeStorageService.isBlockedForEmail(
                        TEST_EMAIL_ADDRESS, CODE_BLOCKED_KEY_PREFIX + codeRequestType))
                .thenReturn(false);
        phoneNumberCodeProcessor =
                new PhoneNumberCodeProcessor(
                        codeStorageService,
                        userContext,
                        configurationService,
                        codeRequest,
                        authenticationService,
                        auditService,
                        accountModifiersService);
    }

    public void setUpPhoneNumberCodeRetryLimitExceeded(CodeRequest codeRequest) {
        when(codeStorageService.getIncorrectMfaCodeAttemptsCount(TEST_EMAIL_ADDRESS)).thenReturn(6);
        when(session.getEmailAddress()).thenReturn(TEST_EMAIL_ADDRESS);
        when(userContext.getSession()).thenReturn(session);
        when(configurationService.isTestClientsEnabled()).thenReturn(false);
        when(codeStorageService.getOtpCode(
                        TEST_EMAIL_ADDRESS, NotificationType.VERIFY_PHONE_NUMBER))
                .thenReturn(Optional.of(VALID_CODE));
        when(codeStorageService.isBlockedForEmail(TEST_EMAIL_ADDRESS, CODE_BLOCKED_KEY_PREFIX))
                .thenReturn(false);
        phoneNumberCodeProcessor =
                new PhoneNumberCodeProcessor(
                        codeStorageService,
                        userContext,
                        configurationService,
                        codeRequest,
                        authenticationService,
                        auditService,
                        accountModifiersService);
    }

    public void setUpBlockedPhoneNumberCode(
            CodeRequest codeRequest, CodeRequestType codeRequestType) {
        when(session.getEmailAddress()).thenReturn(TEST_EMAIL_ADDRESS);
        when(userContext.getSession()).thenReturn(session);
        when(configurationService.isTestClientsEnabled()).thenReturn(false);
        when(codeStorageService.getOtpCode(
                        TEST_EMAIL_ADDRESS, NotificationType.VERIFY_PHONE_NUMBER))
                .thenReturn(Optional.of(VALID_CODE));
        when(codeStorageService.isBlockedForEmail(
                        TEST_EMAIL_ADDRESS, CODE_BLOCKED_KEY_PREFIX + codeRequestType))
                .thenReturn(true);
        phoneNumberCodeProcessor =
                new PhoneNumberCodeProcessor(
                        codeStorageService,
                        userContext,
                        configurationService,
                        codeRequest,
                        authenticationService,
                        auditService,
                        accountModifiersService);
    }
}
