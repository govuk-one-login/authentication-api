package uk.gov.di.authentication.frontendapi.validation;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.entity.CodeRequest;
import uk.gov.di.authentication.entity.VerifyMfaCodeRequest;
import uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.entity.CodeRequestType;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.PriorityIdentifier;
import uk.gov.di.authentication.shared.entity.UserCredentials;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethod;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.helpers.CommonTestVariables;
import uk.gov.di.authentication.shared.helpers.IdGenerator;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoAccountModifiersService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.mfa.MFAMethodsService;
import uk.gov.di.authentication.shared.state.UserContext;
import uk.gov.di.authentication.sharedtest.helper.AuthAppStub;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Stream;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.shared.domain.AuditableEvent.AUDIT_EVENT_EXTENSIONS_ACCOUNT_RECOVERY;
import static uk.gov.di.authentication.shared.domain.AuditableEvent.AUDIT_EVENT_EXTENSIONS_JOURNEY_TYPE;
import static uk.gov.di.authentication.shared.domain.AuditableEvent.AUDIT_EVENT_EXTENSIONS_MFA_METHOD;
import static uk.gov.di.authentication.shared.entity.JourneyType.ACCOUNT_RECOVERY;
import static uk.gov.di.authentication.shared.entity.JourneyType.REGISTRATION;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.BACKUP_AUTH_APP_METHOD;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.BACKUP_SMS_METHOD;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.CLIENT_ID;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.DEFAULT_AUTH_APP_METHOD;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.DEFAULT_SMS_METHOD;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.EMAIL;
import static uk.gov.di.authentication.shared.services.AuditService.MetadataPair.pair;
import static uk.gov.di.authentication.shared.services.CodeStorageService.CODE_BLOCKED_KEY_PREFIX;

class AuthAppCodeProcessorTest {
    AuthAppCodeProcessor authAppCodeProcessor;
    AuthSessionItem authSession;
    CodeStorageService mockCodeStorageService;
    ConfigurationService mockConfigurationService;
    DynamoService mockDynamoService;
    AuditService mockAuditService;
    UserContext mockUserContext;
    DynamoAccountModifiersService mockAccountModifiersService;
    MFAMethodsService mockMfaMethodsService;
    UserProfile mockUserProfile;

    private static final String AUTH_APP_SECRET =
            "JZ5PYIOWNZDAOBA65S5T77FEEKYCCIT2VE4RQDAJD7SO73T3LODA";
    private static final String PERSISTENT_ID = "some-persistent-session-id";
    private static final String CLIENT_SESSION_ID = "a-client-session-id";
    private static final String SESSION_ID = "a-session-id";
    private static final String IP_ADDRESS = "123.123.123.123";
    private static final String INTERNAL_SUB_ID = "urn:fdc:gov.uk:2022:" + IdGenerator.generate();
    private static final String TXMA_ENCODED_HEADER_VALUE = "txma-test-value";
    private final int MAX_RETRIES = 5;

    private final AuditContext auditContext =
            new AuditContext(
                    CLIENT_ID,
                    CLIENT_SESSION_ID,
                    SESSION_ID,
                    INTERNAL_SUB_ID,
                    CommonTestVariables.EMAIL,
                    IP_ADDRESS,
                    AuditService.UNKNOWN,
                    PERSISTENT_ID,
                    Optional.of(TXMA_ENCODED_HEADER_VALUE),
                    new ArrayList<>());

    @BeforeEach
    void setUp() {
        this.authSession =
                new AuthSessionItem()
                        .withSessionId(SESSION_ID)
                        .withEmailAddress(EMAIL)
                        .withInternalCommonSubjectId(INTERNAL_SUB_ID)
                        .withClientId(CLIENT_ID);
        this.mockCodeStorageService = mock(CodeStorageService.class);
        this.mockConfigurationService = mock(ConfigurationService.class);
        this.mockDynamoService = mock(DynamoService.class);
        this.mockAuditService = mock(AuditService.class);
        this.mockUserContext = mock(UserContext.class);
        this.mockAccountModifiersService = mock(DynamoAccountModifiersService.class);
        this.mockMfaMethodsService = mock(MFAMethodsService.class);
        this.mockUserProfile = mock(UserProfile.class);
        when(mockUserContext.getAuthSession()).thenReturn(authSession);
        when(mockDynamoService.getUserProfileByEmail(EMAIL))
                .thenReturn(new UserProfile().withMfaMethodsMigrated(false));
        when(mockConfigurationService.getAuthAppCodeAllowedWindows()).thenReturn(9);
        when(mockConfigurationService.getAuthAppCodeWindowLength()).thenReturn(30);
    }

    private static Stream<Arguments> validatorParams() {
        return Stream.of(
                Arguments.of(JourneyType.SIGN_IN, null, CodeRequestType.MFA_SIGN_IN),
                Arguments.of(
                        JourneyType.PASSWORD_RESET_MFA, null, CodeRequestType.MFA_PW_RESET_MFA),
                Arguments.of(
                        JourneyType.REGISTRATION,
                        AUTH_APP_SECRET,
                        CodeRequestType.MFA_REGISTRATION),
                Arguments.of(
                        JourneyType.REAUTHENTICATION, null, CodeRequestType.MFA_REAUTHENTICATION));
    }

    @ParameterizedTest
    @MethodSource("validatorParams")
    void returnsNoErrorOnValidAuthCode(JourneyType journeyType, String authAppSecret) {
        var authAppStub = new AuthAppStub();
        var authCode =
                authAppStub.getAuthAppOneTimeCode(AUTH_APP_SECRET, NowHelper.now().getTime());
        setUpValidAuthCode(
                new VerifyMfaCodeRequest(
                        MFAMethodType.AUTH_APP, authCode, journeyType, authAppSecret));

        assertEquals(Optional.empty(), authAppCodeProcessor.validateCode());
    }

    private static Stream<Arguments> validatorParamsWithoutRegistrationJourney() {
        return Stream.of(
                Arguments.of(JourneyType.SIGN_IN, null, CodeRequestType.MFA_SIGN_IN),
                Arguments.of(
                        JourneyType.PASSWORD_RESET_MFA, null, CodeRequestType.MFA_PW_RESET_MFA),
                Arguments.of(
                        JourneyType.REAUTHENTICATION, null, CodeRequestType.MFA_REAUTHENTICATION));
    }

    @ParameterizedTest
    @MethodSource("validatorParamsWithoutRegistrationJourney")
    void returnsNoErrorOnValidAuthCodeForMigratedUser(JourneyType journeyType) {
        when(mockCodeStorageService.isBlockedForEmail(EMAIL, CODE_BLOCKED_KEY_PREFIX))
                .thenReturn(false);

        var userCredentials =
                new UserCredentials()
                        .withMfaMethods(List.of(DEFAULT_AUTH_APP_METHOD, BACKUP_SMS_METHOD));
        when(mockDynamoService.getUserCredentialsFromEmail(EMAIL)).thenReturn(userCredentials);
        when(mockDynamoService.getUserProfileByEmail(EMAIL))
                .thenReturn(new UserProfile().withMfaMethodsMigrated(true));

        var secretForMigratedAuthApp = DEFAULT_AUTH_APP_METHOD.getCredentialValue();

        var authAppStub = new AuthAppStub();
        var authCode =
                authAppStub.getAuthAppOneTimeCode(
                        secretForMigratedAuthApp, NowHelper.now().getTime());

        var codeRequest = new VerifyMfaCodeRequest(MFAMethodType.AUTH_APP, authCode, journeyType);

        this.authAppCodeProcessor =
                new AuthAppCodeProcessor(
                        mockUserContext,
                        mockCodeStorageService,
                        mockConfigurationService,
                        mockDynamoService,
                        MAX_RETRIES,
                        codeRequest,
                        mockAuditService,
                        mockAccountModifiersService,
                        mockMfaMethodsService);

        assertEquals(Optional.empty(), authAppCodeProcessor.validateCode());
    }

    @ParameterizedTest
    @MethodSource("validatorParamsWithoutRegistrationJourney")
    void returnsNoErrorOnValidAuthCodeToBackupMethodForMigratedUser(JourneyType journeyType) {
        when(mockCodeStorageService.isBlockedForEmail(EMAIL, CODE_BLOCKED_KEY_PREFIX))
                .thenReturn(false);

        var userCredentials =
                new UserCredentials()
                        .withMfaMethods(List.of(BACKUP_AUTH_APP_METHOD, DEFAULT_SMS_METHOD));
        when(mockDynamoService.getUserCredentialsFromEmail(EMAIL)).thenReturn(userCredentials);
        when(mockDynamoService.getUserProfileByEmail(EMAIL))
                .thenReturn(new UserProfile().withMfaMethodsMigrated(true));

        var secretForMigratedAuthApp = BACKUP_AUTH_APP_METHOD.getCredentialValue();

        var authAppStub = new AuthAppStub();
        var authCode =
                authAppStub.getAuthAppOneTimeCode(
                        secretForMigratedAuthApp, NowHelper.now().getTime());

        var codeRequest = new VerifyMfaCodeRequest(MFAMethodType.AUTH_APP, authCode, journeyType);

        this.authAppCodeProcessor =
                new AuthAppCodeProcessor(
                        mockUserContext,
                        mockCodeStorageService,
                        mockConfigurationService,
                        mockDynamoService,
                        MAX_RETRIES,
                        codeRequest,
                        mockAuditService,
                        mockAccountModifiersService,
                        mockMfaMethodsService);

        assertEquals(Optional.empty(), authAppCodeProcessor.validateCode());
    }

    @ParameterizedTest
    @MethodSource("validatorParams")
    void returnsCorrectErrorWhenCodeBlockedForEmailAddress(
            JourneyType journeyType, String authAppSecret, CodeRequestType codeRequestType) {
        setUpBlockedUser(
                new VerifyMfaCodeRequest(
                        MFAMethodType.AUTH_APP, "000000", journeyType, authAppSecret),
                codeRequestType);

        assertEquals(Optional.of(ErrorResponse.ERROR_1042), authAppCodeProcessor.validateCode());
    }

    @ParameterizedTest
    @MethodSource("validatorParams")
    void returnsCorrectErrorWhenRetryLimitExceeded(JourneyType journeyType, String authAppSecret) {
        setUpRetryLimitExceededUser(
                new VerifyMfaCodeRequest(
                        MFAMethodType.AUTH_APP, "000000", journeyType, authAppSecret));

        assertEquals(Optional.of(ErrorResponse.ERROR_1042), authAppCodeProcessor.validateCode());
    }

    @ParameterizedTest
    @MethodSource("validatorParams")
    void returnsCorrectErrorWhenNoAuthCodeIsFound(JourneyType journeyType) {
        setUpNoAuthCodeForUser(
                new VerifyMfaCodeRequest(MFAMethodType.AUTH_APP, "000000", journeyType));

        assertEquals(Optional.of(ErrorResponse.ERROR_1081), authAppCodeProcessor.validateCode());
    }

    @Test
    void shouldReturnErrorWhenAuthAppSecretIsInvalid() {
        setUpValidAuthCode(
                new VerifyMfaCodeRequest(
                        MFAMethodType.AUTH_APP,
                        "000000",
                        JourneyType.REGISTRATION,
                        "not-base-32-encoded-secret"));

        assertThat(
                authAppCodeProcessor.validateCode(),
                equalTo(Optional.of(ErrorResponse.ERROR_1041)));
    }

    @ParameterizedTest
    @MethodSource("validatorParams")
    void returnsCorrectErrorWhenAuthCodeIsInvalid(JourneyType journeyType, String authAppSecret) {
        setUpValidAuthCode(
                new VerifyMfaCodeRequest(
                        MFAMethodType.AUTH_APP, "111111", journeyType, authAppSecret));

        assertEquals(Optional.of(ErrorResponse.ERROR_1043), authAppCodeProcessor.validateCode());
    }

    @ParameterizedTest
    @MethodSource("validatorParams")
    void returnsCorrectErrorWhenOtpCodeIsMissing(JourneyType journeyType, String authAppSecret) {
        setUpValidAuthCode(
                new VerifyMfaCodeRequest(MFAMethodType.AUTH_APP, "", journeyType, authAppSecret));

        assertEquals(Optional.of(ErrorResponse.ERROR_1043), authAppCodeProcessor.validateCode());
    }

    @ParameterizedTest
    @MethodSource("validatorParams")
    void returnsCorrectErrorWhenOtpCodeIsTooLong(JourneyType journeyType, String authAppSecret) {
        setUpValidAuthCode(
                new VerifyMfaCodeRequest(
                        MFAMethodType.AUTH_APP, "999999999999", journeyType, authAppSecret));

        assertEquals(Optional.of(ErrorResponse.ERROR_1043), authAppCodeProcessor.validateCode());
    }

    @Test
    void shouldUpdateDynamoAndCreateAuditEventWhenRegistration() {
        setUpSuccessfulCodeRequest(
                new VerifyMfaCodeRequest(
                        MFAMethodType.AUTH_APP,
                        "111111",
                        JourneyType.REGISTRATION,
                        AUTH_APP_SECRET));

        authAppCodeProcessor.processSuccessfulCodeRequest(
                IP_ADDRESS, PERSISTENT_ID, mockUserProfile);

        verify(mockDynamoService, never())
                .setVerifiedAuthAppAndRemoveExistingMfaMethod(anyString(), anyString());
        verify(mockDynamoService)
                .setAuthAppAndAccountVerified(CommonTestVariables.EMAIL, AUTH_APP_SECRET);

        ArgumentCaptor<AuditService.MetadataPair[]> captor =
                ArgumentCaptor.forClass(AuditService.MetadataPair[].class);

        verify(mockAuditService)
                .submitAuditEvent(
                        eq(FrontendAuditableEvent.AUTH_UPDATE_PROFILE_AUTH_APP),
                        eq(auditContext),
                        captor.capture());

        AuditService.MetadataPair[] actual = captor.getValue();
        List<AuditService.MetadataPair> expected =
                new ArrayList<>(
                        List.of(
                                AuditService.MetadataPair.pair(
                                        "mfa-type", MFAMethodType.AUTH_APP.getValue()),
                                AuditService.MetadataPair.pair(
                                        AUDIT_EVENT_EXTENSIONS_ACCOUNT_RECOVERY, false),
                                AuditService.MetadataPair.pair(
                                        AUDIT_EVENT_EXTENSIONS_MFA_METHOD,
                                        PriorityIdentifier.DEFAULT),
                                AuditService.MetadataPair.pair(
                                        AUDIT_EVENT_EXTENSIONS_JOURNEY_TYPE, REGISTRATION)));

        assertTrue(expected.containsAll(Arrays.asList(actual)));
        assertTrue(Arrays.asList(actual).containsAll(expected));
    }

    @Test
    void shouldCallDynamoToUpdateMfaMethodAndCreateAuditEventWhenAccountRecovery() {
        when(mockUserProfile.isMfaMethodsMigrated()).thenReturn(false);
        setUpSuccessfulCodeRequest(
                new VerifyMfaCodeRequest(
                        MFAMethodType.AUTH_APP,
                        "111111",
                        JourneyType.ACCOUNT_RECOVERY,
                        AUTH_APP_SECRET));

        authAppCodeProcessor.processSuccessfulCodeRequest(
                IP_ADDRESS, PERSISTENT_ID, mockUserProfile);

        verify(mockDynamoService, never()).setAuthAppAndAccountVerified(anyString(), anyString());
        verify(mockDynamoService)
                .setVerifiedAuthAppAndRemoveExistingMfaMethod(
                        CommonTestVariables.EMAIL, AUTH_APP_SECRET);

        ArgumentCaptor<AuditService.MetadataPair[]> captor =
                ArgumentCaptor.forClass(AuditService.MetadataPair[].class);

        verify(mockAuditService)
                .submitAuditEvent(
                        eq(FrontendAuditableEvent.AUTH_UPDATE_PROFILE_AUTH_APP),
                        eq(auditContext),
                        captor.capture());

        AuditService.MetadataPair[] actual = captor.getValue();
        AuditService.MetadataPair[] expected =
                new AuditService.MetadataPair[] {
                    AuditService.MetadataPair.pair("mfa-type", MFAMethodType.AUTH_APP.getValue()),
                    AuditService.MetadataPair.pair(
                            AUDIT_EVENT_EXTENSIONS_MFA_METHOD, PriorityIdentifier.DEFAULT),
                    AuditService.MetadataPair.pair(AUDIT_EVENT_EXTENSIONS_ACCOUNT_RECOVERY, true),
                    AuditService.MetadataPair.pair(
                            AUDIT_EVENT_EXTENSIONS_JOURNEY_TYPE, ACCOUNT_RECOVERY)
                };

        assertTrue(Arrays.asList(expected).containsAll(Arrays.asList(actual)));
        assertTrue(Arrays.asList(actual).containsAll(Arrays.asList(expected)));
    }

    @Test
    void shouldResetMigratedUsersMfaMethodsWhenMfaMigratedUserGoesThroughAccountRecovery() {
        when(mockUserProfile.isMfaMethodsMigrated()).thenReturn(true);

        setUpSuccessfulCodeRequest(
                new VerifyMfaCodeRequest(
                        MFAMethodType.AUTH_APP,
                        "111111",
                        JourneyType.ACCOUNT_RECOVERY,
                        AUTH_APP_SECRET));

        authAppCodeProcessor.processSuccessfulCodeRequest(
                IP_ADDRESS, PERSISTENT_ID, mockUserProfile);

        ArgumentCaptor<MFAMethod> mfaMethodCaptor = ArgumentCaptor.forClass(MFAMethod.class);
        verify(mockMfaMethodsService)
                .deleteMigratedMFAsAndCreateNewDefault(eq(EMAIL), mfaMethodCaptor.capture());
        var capturedMfaMethod = mfaMethodCaptor.getValue();
        assertTrue(capturedMfaMethod.isMethodVerified());
        assertTrue(capturedMfaMethod.isEnabled());
        assertEquals(AUTH_APP_SECRET, capturedMfaMethod.getCredentialValue());
        assertEquals(PriorityIdentifier.DEFAULT.toString(), capturedMfaMethod.getPriority());
        assertInstanceOf(UUID.class, UUID.fromString(capturedMfaMethod.getMfaIdentifier()));

        verify(mockDynamoService, never()).setAuthAppAndAccountVerified(anyString(), anyString());

        ArgumentCaptor<AuditService.MetadataPair[]> captor =
                ArgumentCaptor.forClass(AuditService.MetadataPair[].class);

        verify(mockAuditService)
                .submitAuditEvent(
                        eq(FrontendAuditableEvent.AUTH_UPDATE_PROFILE_AUTH_APP),
                        eq(auditContext),
                        captor.capture());

        AuditService.MetadataPair[] actual = captor.getValue();
        List<AuditService.MetadataPair> expected =
                new ArrayList<>(
                        List.of(
                                AuditService.MetadataPair.pair(
                                        "mfa-type", MFAMethodType.AUTH_APP.getValue()),
                                AuditService.MetadataPair.pair(
                                        AUDIT_EVENT_EXTENSIONS_ACCOUNT_RECOVERY, true),
                                AuditService.MetadataPair.pair(
                                        AUDIT_EVENT_EXTENSIONS_MFA_METHOD,
                                        PriorityIdentifier.DEFAULT),
                                AuditService.MetadataPair.pair(
                                        AUDIT_EVENT_EXTENSIONS_JOURNEY_TYPE, ACCOUNT_RECOVERY)));

        assertTrue(expected.containsAll(Arrays.asList(actual)));
        assertTrue(Arrays.asList(actual).containsAll(expected));
    }

    @Test
    void shouldClearAccountRecoveryBlockAndCreateAuditEventWhenSignInAndBlockIsPresent() {
        when(mockAccountModifiersService.isAccountRecoveryBlockPresent(INTERNAL_SUB_ID))
                .thenReturn(true);
        setUpSuccessfulCodeRequest(
                new VerifyMfaCodeRequest(MFAMethodType.AUTH_APP, "111111", JourneyType.SIGN_IN));

        authAppCodeProcessor.processSuccessfulCodeRequest(
                IP_ADDRESS, PERSISTENT_ID, mockUserProfile);

        verifyNoInteractions(mockDynamoService);
        verify(mockAccountModifiersService).removeAccountRecoveryBlockIfPresent(INTERNAL_SUB_ID);
        verify(mockAuditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.AUTH_ACCOUNT_RECOVERY_BLOCK_REMOVED,
                        auditContext,
                        pair("mfa-type", MFAMethodType.AUTH_APP.getValue()));
    }

    @Test
    void shouldNotClearAccountRecoveryBlockAndCreateAuditEventWhenSignInAndBlockIsNotresent() {
        when(mockAccountModifiersService.isAccountRecoveryBlockPresent(INTERNAL_SUB_ID))
                .thenReturn(false);
        setUpSuccessfulCodeRequest(
                new VerifyMfaCodeRequest(MFAMethodType.AUTH_APP, "111111", JourneyType.SIGN_IN));

        authAppCodeProcessor.processSuccessfulCodeRequest(
                IP_ADDRESS, PERSISTENT_ID, mockUserProfile);

        verifyNoInteractions(mockDynamoService);
        verify(mockAccountModifiersService, never())
                .removeAccountRecoveryBlockIfPresent(anyString());
        verifyNoInteractions(mockAuditService);
    }

    private void setUpSuccessfulCodeRequest(CodeRequest codeRequest) {
        when(mockUserContext.getClientSessionId()).thenReturn(CLIENT_SESSION_ID);
        when(mockUserContext.getAuthSession()).thenReturn(authSession);
        when(mockUserContext.getTxmaAuditEncoded()).thenReturn(TXMA_ENCODED_HEADER_VALUE);

        this.authAppCodeProcessor =
                new AuthAppCodeProcessor(
                        mockUserContext,
                        mockCodeStorageService,
                        mockConfigurationService,
                        mockDynamoService,
                        MAX_RETRIES,
                        codeRequest,
                        mockAuditService,
                        mockAccountModifiersService,
                        mockMfaMethodsService);
    }

    private void setUpBlockedUser(CodeRequest codeRequest, CodeRequestType codeRequestType) {
        when(mockCodeStorageService.isBlockedForEmail(
                        EMAIL, CODE_BLOCKED_KEY_PREFIX + codeRequestType))
                .thenReturn(true);

        this.authAppCodeProcessor =
                new AuthAppCodeProcessor(
                        mockUserContext,
                        mockCodeStorageService,
                        mockConfigurationService,
                        mockDynamoService,
                        MAX_RETRIES,
                        codeRequest,
                        mockAuditService,
                        mockAccountModifiersService,
                        mockMfaMethodsService);
    }

    private void setUpRetryLimitExceededUser(CodeRequest codeRequest) {
        when(mockCodeStorageService.isBlockedForEmail(EMAIL, CODE_BLOCKED_KEY_PREFIX))
                .thenReturn(false);
        when(mockCodeStorageService.getIncorrectMfaCodeAttemptsCount(EMAIL))
                .thenReturn(MAX_RETRIES + 1);

        this.authAppCodeProcessor =
                new AuthAppCodeProcessor(
                        mockUserContext,
                        mockCodeStorageService,
                        mockConfigurationService,
                        mockDynamoService,
                        MAX_RETRIES,
                        codeRequest,
                        mockAuditService,
                        mockAccountModifiersService,
                        mockMfaMethodsService);
    }

    private void setUpNoAuthCodeForUser(CodeRequest codeRequest) {
        when(mockCodeStorageService.isBlockedForEmail(EMAIL, CODE_BLOCKED_KEY_PREFIX))
                .thenReturn(false);
        when(mockDynamoService.getUserCredentialsFromEmail(EMAIL))
                .thenReturn(new UserCredentials().withMfaMethods(List.of()));

        this.authAppCodeProcessor =
                new AuthAppCodeProcessor(
                        mockUserContext,
                        mockCodeStorageService,
                        mockConfigurationService,
                        mockDynamoService,
                        MAX_RETRIES,
                        codeRequest,
                        mockAuditService,
                        mockAccountModifiersService,
                        mockMfaMethodsService);
    }

    private void setUpValidAuthCode(CodeRequest codeRequest) {
        when(mockCodeStorageService.isBlockedForEmail(EMAIL, CODE_BLOCKED_KEY_PREFIX))
                .thenReturn(false);

        var mfaMethod =
                new MFAMethod()
                        .withMfaMethodType(MFAMethodType.AUTH_APP.name())
                        .withCredentialValue(AUTH_APP_SECRET)
                        .withEnabled(true);
        var userCredentials = new UserCredentials().withMfaMethods(List.of(mfaMethod));
        when(mockDynamoService.getUserCredentialsFromEmail(EMAIL)).thenReturn(userCredentials);

        this.authAppCodeProcessor =
                new AuthAppCodeProcessor(
                        mockUserContext,
                        mockCodeStorageService,
                        mockConfigurationService,
                        mockDynamoService,
                        MAX_RETRIES,
                        codeRequest,
                        mockAuditService,
                        mockAccountModifiersService,
                        mockMfaMethodsService);
    }
}
