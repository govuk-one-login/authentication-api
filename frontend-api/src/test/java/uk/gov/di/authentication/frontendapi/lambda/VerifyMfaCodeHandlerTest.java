package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.authentication.entity.CodeRequest;
import uk.gov.di.authentication.entity.VerifyMfaCodeRequest;
import uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent;
import uk.gov.di.authentication.frontendapi.services.DynamoAccountRecoveryBlockService;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.ClientSession;
import uk.gov.di.authentication.shared.entity.CredentialTrustLevel;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.MFAMethodType;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.entity.VectorOfTrust;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.helpers.SaltHelper;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.SerializationService;
import uk.gov.di.authentication.shared.services.SessionService;
import uk.gov.di.authentication.shared.validation.AuthAppCodeValidator;
import uk.gov.di.authentication.shared.validation.MfaCodeValidatorFactory;
import uk.gov.di.authentication.shared.validation.PhoneNumberCodeValidator;
import uk.gov.di.authentication.sharedtest.logging.CaptureLoggingExtension;

import java.net.URI;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.not;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.shared.services.AuditService.MetadataPair.pair;
import static uk.gov.di.authentication.shared.services.CodeStorageService.CODE_BLOCKED_KEY_PREFIX;
import static uk.gov.di.authentication.sharedtest.helper.RequestEventHelper.contextWithSourceIp;
import static uk.gov.di.authentication.sharedtest.logging.LogEventMatcher.withMessageContaining;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class VerifyMfaCodeHandlerTest {

    private static final String TEST_EMAIL_ADDRESS = "test@test.com";
    private static final String CODE = "123456";
    private static final String CLIENT_ID = "client-id";
    private static final String CLIENT_NAME = "client-name";
    private static final String TEST_CLIENT_CODE = "654321";
    private static final String CLIENT_SESSION_ID = "client-session-id";
    private static final String SUBJECT_ID = "test-subject-id";
    private static final String PHONE_NUMBER = "+447700900000";
    private static final String AUTH_APP_SECRET =
            "JZ5PYIOWNZDAOBA65S5T77FEEKYCCIT2VE4RQDAJD7SO73T3LODA";
    private final String expectedCommonSubject =
            ClientSubjectHelper.calculatePairwiseIdentifier(
                    new Subject().getValue(), "test.account.gov.uk", SaltHelper.generateNewSalt());
    private final Session session =
            new Session("session-id")
                    .setEmailAddress(TEST_EMAIL_ADDRESS)
                    .setInternalCommonSubjectIdentifier(expectedCommonSubject);
    private final Json objectMapper = SerializationService.getInstance();
    public VerifyMfaCodeHandler handler;

    private final Context context = mock(Context.class);
    private final SessionService sessionService = mock(SessionService.class);
    private final CodeStorageService codeStorageService = mock(CodeStorageService.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final DynamoAccountRecoveryBlockService accountRecoveryBlockService =
            mock(DynamoAccountRecoveryBlockService.class);
    private final MfaCodeValidatorFactory mfaCodeValidatorFactory =
            mock(MfaCodeValidatorFactory.class);
    private final AuthAppCodeValidator authAppCodeValidator = mock(AuthAppCodeValidator.class);
    private final PhoneNumberCodeValidator phoneNumberCodeValidator =
            mock(PhoneNumberCodeValidator.class);
    private final ClientSessionService clientSessionService = mock(ClientSessionService.class);
    private final ClientRegistry clientRegistry = mock(ClientRegistry.class);
    private final ClientService clientService = mock(ClientService.class);
    private final UserProfile userProfile = mock(UserProfile.class);
    private final AuthenticationService authenticationService = mock(AuthenticationService.class);
    private final ClientSession clientSession = mock(ClientSession.class);
    private final AuditService auditService = mock(AuditService.class);
    private final CloudwatchMetricsService cloudwatchMetricsService =
            mock(CloudwatchMetricsService.class);

    @RegisterExtension
    private final CaptureLoggingExtension logging =
            new CaptureLoggingExtension(VerifyCodeHandler.class);

    @BeforeEach
    void setUp() {
        when(authenticationService.getUserProfileFromEmail(TEST_EMAIL_ADDRESS))
                .thenReturn(Optional.of(userProfile));
        when(clientService.getClient(CLIENT_ID)).thenReturn(Optional.of(clientRegistry));
        when(clientRegistry.getClientID()).thenReturn(CLIENT_ID);
        when(clientRegistry.getClientName()).thenReturn(CLIENT_NAME);

        when(clientSession.getAuthRequestParams())
                .thenReturn(withAuthenticationRequest().toParameters());

        when(userProfile.getSubjectID()).thenReturn(SUBJECT_ID);
        when(configurationService.getBlockedEmailDuration()).thenReturn(900L);
        when(configurationService.getCodeMaxRetries()).thenReturn(5);
        when(clientSessionService.getClientSession(CLIENT_SESSION_ID))
                .thenReturn(Optional.of(clientSession));

        handler =
                new VerifyMfaCodeHandler(
                        configurationService,
                        sessionService,
                        clientSessionService,
                        clientService,
                        authenticationService,
                        codeStorageService,
                        auditService,
                        mfaCodeValidatorFactory,
                        cloudwatchMetricsService,
                        accountRecoveryBlockService);
    }

    @AfterEach
    void tearDown() {
        assertThat(
                logging.events(),
                not(
                        hasItem(
                                withMessageContaining(
                                        CLIENT_ID,
                                        TEST_CLIENT_CODE,
                                        session.getSessionId(),
                                        CLIENT_SESSION_ID))));
    }

    private static Stream<CredentialTrustLevel> credentialTrustLevels() {
        return Stream.of(CredentialTrustLevel.LOW_LEVEL, CredentialTrustLevel.MEDIUM_LEVEL);
    }

    @ParameterizedTest
    @MethodSource("credentialTrustLevels")
    void shouldReturn204WhenSuccessfulAuthAppCodeRegistrationRequestAndSetMfaMethod(
            CredentialTrustLevel credentialTrustLevel) throws Json.JsonException {
        when(mfaCodeValidatorFactory.getMfaCodeValidator(any(), any(JourneyType.class), any()))
                .thenReturn(Optional.of(authAppCodeValidator));
        when(authAppCodeValidator.validateCode(any(CodeRequest.class)))
                .thenReturn(Optional.empty());
        session.setNewAccount(Session.AccountState.NEW);
        session.setCurrentCredentialStrength(credentialTrustLevel);
        var result =
                makeCallWithCode(
                        new VerifyMfaCodeRequest(
                                MFAMethodType.AUTH_APP, CODE, true, JourneyType.REGISTRATION, AUTH_APP_SECRET));

        assertThat(result, hasStatus(204));
        assertThat(session.getVerifiedMfaMethodType(), equalTo(MFAMethodType.AUTH_APP));
        assertThat(
                session.getCurrentCredentialStrength(), equalTo(CredentialTrustLevel.MEDIUM_LEVEL));
        verify(authenticationService)
                .updateMFAMethod(
                        TEST_EMAIL_ADDRESS, MFAMethodType.AUTH_APP, true, true, AUTH_APP_SECRET);
        verify(authenticationService).setAccountVerified(TEST_EMAIL_ADDRESS);
        verify(codeStorageService, never())
                .saveBlockedForEmail(TEST_EMAIL_ADDRESS, CODE_BLOCKED_KEY_PREFIX, 900L);
        verify(codeStorageService, never()).deleteIncorrectMfaCodeAttemptsCount(TEST_EMAIL_ADDRESS);
        verify(accountRecoveryBlockService).deleteBlockIfPresent(TEST_EMAIL_ADDRESS);

        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.CODE_VERIFIED,
                        CLIENT_SESSION_ID,
                        session.getSessionId(),
                        CLIENT_ID,
                        expectedCommonSubject,
                        TEST_EMAIL_ADDRESS,
                        "123.123.123.123",
                        AuditService.UNKNOWN,
                        PersistentIdHelper.PERSISTENT_ID_UNKNOWN_VALUE,
                        pair("mfa-type", MFAMethodType.AUTH_APP.getValue()));
        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.UPDATE_PROFILE_AUTH_APP,
                        CLIENT_SESSION_ID,
                        session.getSessionId(),
                        CLIENT_ID,
                        expectedCommonSubject,
                        TEST_EMAIL_ADDRESS,
                        "123.123.123.123",
                        AuditService.UNKNOWN,
                        PersistentIdHelper.PERSISTENT_ID_UNKNOWN_VALUE,
                        pair("mfa-type", MFAMethodType.AUTH_APP.getValue()));
        verify(cloudwatchMetricsService)
                .incrementAuthenticationSuccess(
                        Session.AccountState.NEW, CLIENT_ID, CLIENT_NAME, "P0", false, true);
    }

    @ParameterizedTest
    @MethodSource("credentialTrustLevels")
    void shouldReturn204WhenSuccessfulPhoneCodeRegistrationRequestAndSetPhoneNumber(
            CredentialTrustLevel credentialTrustLevel) throws Json.JsonException {
        when(mfaCodeValidatorFactory.getMfaCodeValidator(any(), any(JourneyType.class), any()))
                .thenReturn(Optional.of(phoneNumberCodeValidator));
        when(phoneNumberCodeValidator.validateCode(any(CodeRequest.class)))
                .thenReturn(Optional.empty());
        session.setNewAccount(Session.AccountState.NEW);
        session.setCurrentCredentialStrength(credentialTrustLevel);
        var result =
                makeCallWithCode(
                        new VerifyMfaCodeRequest(MFAMethodType.SMS, CODE, true, JourneyType.REGISTRATION, PHONE_NUMBER));

        assertThat(result, hasStatus(204));
        assertThat(session.getVerifiedMfaMethodType(), equalTo(MFAMethodType.SMS));
        assertThat(
                session.getCurrentCredentialStrength(), equalTo(CredentialTrustLevel.MEDIUM_LEVEL));
        verify(authenticationService)
                .updatePhoneNumberAndAccountVerifiedStatus(
                        TEST_EMAIL_ADDRESS, PHONE_NUMBER, true, true);
        verify(codeStorageService, never())
                .saveBlockedForEmail(TEST_EMAIL_ADDRESS, CODE_BLOCKED_KEY_PREFIX, 900L);
        verify(codeStorageService, never()).deleteIncorrectMfaCodeAttemptsCount(TEST_EMAIL_ADDRESS);
        verify(accountRecoveryBlockService).deleteBlockIfPresent(TEST_EMAIL_ADDRESS);
        verify(authenticationService)
                .setMFAMethodEnabled(TEST_EMAIL_ADDRESS, MFAMethodType.AUTH_APP, false);

        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.CODE_VERIFIED,
                        CLIENT_SESSION_ID,
                        session.getSessionId(),
                        CLIENT_ID,
                        expectedCommonSubject,
                        TEST_EMAIL_ADDRESS,
                        "123.123.123.123",
                        AuditService.UNKNOWN,
                        PersistentIdHelper.PERSISTENT_ID_UNKNOWN_VALUE,
                        pair("mfa-type", MFAMethodType.SMS.getValue()));
        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.UPDATE_PROFILE_PHONE_NUMBER,
                        CLIENT_SESSION_ID,
                        session.getSessionId(),
                        CLIENT_ID,
                        expectedCommonSubject,
                        TEST_EMAIL_ADDRESS,
                        "123.123.123.123",
                        PHONE_NUMBER,
                        PersistentIdHelper.PERSISTENT_ID_UNKNOWN_VALUE,
                        pair("mfa-type", MFAMethodType.SMS.getValue()));
        verify(cloudwatchMetricsService)
                .incrementAuthenticationSuccess(
                        Session.AccountState.NEW, CLIENT_ID, CLIENT_NAME, "P0", false, true);
    }

    @Test
    void shouldReturn204WhenSuccessfulAuthAppCodeLoginRequest() throws Json.JsonException {
        when(mfaCodeValidatorFactory.getMfaCodeValidator(any(), any(JourneyType.class), any()))
                .thenReturn(Optional.of(authAppCodeValidator));
        when(authAppCodeValidator.validateCode(any(CodeRequest.class)))
                .thenReturn(Optional.empty());
        session.setNewAccount(Session.AccountState.EXISTING);
        var codeRequest = new VerifyMfaCodeRequest(MFAMethodType.AUTH_APP, CODE, false, JourneyType.REGISTRATION);
        var result = makeCallWithCode(codeRequest);

        assertThat(result, hasStatus(204));
        assertThat(session.getVerifiedMfaMethodType(), equalTo(MFAMethodType.AUTH_APP));
        verify(codeStorageService, never())
                .saveBlockedForEmail(TEST_EMAIL_ADDRESS, CODE_BLOCKED_KEY_PREFIX, 900L);
        verify(codeStorageService, never()).deleteIncorrectMfaCodeAttemptsCount(TEST_EMAIL_ADDRESS);
        verify(authenticationService, never())
                .updateMFAMethod(any(), any(), anyBoolean(), anyBoolean(), any());
        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.CODE_VERIFIED,
                        CLIENT_SESSION_ID,
                        session.getSessionId(),
                        CLIENT_ID,
                        expectedCommonSubject,
                        TEST_EMAIL_ADDRESS,
                        "123.123.123.123",
                        AuditService.UNKNOWN,
                        PersistentIdHelper.PERSISTENT_ID_UNKNOWN_VALUE,
                        pair("mfa-type", MFAMethodType.AUTH_APP.getValue()));
        verify(cloudwatchMetricsService)
                .incrementAuthenticationSuccess(
                        Session.AccountState.EXISTING, CLIENT_ID, CLIENT_NAME, "P0", false, true);
    }

    @Test
    void shouldReturn400IfMfaCodeValidatorCannotBeFound() throws Json.JsonException {
        when(mfaCodeValidatorFactory.getMfaCodeValidator(any(), any(JourneyType.class), any()))
                .thenReturn(Optional.empty());
        var codeRequest =
                new VerifyMfaCodeRequest(MFAMethodType.AUTH_APP, CODE, true, JourneyType.REGISTRATION, AUTH_APP_SECRET);
        var result = makeCallWithCode(codeRequest);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1002));
        assertThat(session.getVerifiedMfaMethodType(), equalTo(null));
        verify(authenticationService, never()).setAccountVerified(TEST_EMAIL_ADDRESS);
        verifyNoInteractions(auditService);
        verifyNoInteractions(authAppCodeValidator);
        verifyNoInteractions(codeStorageService);
        verifyNoInteractions(accountRecoveryBlockService);
    }

    private static Stream<Boolean> registration() {
        return Stream.of(true, false);
    }

    @Test
    void shouldReturn400AndBlockCodeWhenUserEnteredInvalidAuthAppCodeTooManyTimes()
            throws Json.JsonException {
        when(mfaCodeValidatorFactory.getMfaCodeValidator(any(), any(JourneyType.class), any()))
                .thenReturn(Optional.of(authAppCodeValidator));
        when(authAppCodeValidator.validateCode(any(CodeRequest.class)))
                .thenReturn(Optional.of(ErrorResponse.ERROR_1042));
        var codeRequest = new VerifyMfaCodeRequest(MFAMethodType.AUTH_APP, CODE, false, JourneyType.REGISTRATION);
        var result = makeCallWithCode(codeRequest);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1042));
        assertThat(session.getVerifiedMfaMethodType(), equalTo(null));
        verify(codeStorageService)
                .saveBlockedForEmail(TEST_EMAIL_ADDRESS, CODE_BLOCKED_KEY_PREFIX, 900L);
        verify(authenticationService, never()).setAccountVerified(TEST_EMAIL_ADDRESS);
        verify(codeStorageService)
                .deleteIncorrectMfaCodeAttemptsCount(TEST_EMAIL_ADDRESS, MFAMethodType.AUTH_APP);
        verifyNoInteractions(accountRecoveryBlockService);
        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.CODE_MAX_RETRIES_REACHED,
                        CLIENT_SESSION_ID,
                        session.getSessionId(),
                        CLIENT_ID,
                        expectedCommonSubject,
                        TEST_EMAIL_ADDRESS,
                        "123.123.123.123",
                        AuditService.UNKNOWN,
                        PersistentIdHelper.PERSISTENT_ID_UNKNOWN_VALUE,
                        pair("mfa-type", MFAMethodType.AUTH_APP.getValue()));
    }

    @Test
    void shouldReturn400AndNotBlockCodeWhenUserEnteredInvalidAuthAppCodeAndBlockAlreadyExists()
            throws Json.JsonException {
        when(mfaCodeValidatorFactory.getMfaCodeValidator(any(), any(JourneyType.class), any()))
                .thenReturn(Optional.of(authAppCodeValidator));
        when(authAppCodeValidator.validateCode(any(CodeRequest.class)))
                .thenReturn(Optional.of(ErrorResponse.ERROR_1042));
        when(codeStorageService.isBlockedForEmail(TEST_EMAIL_ADDRESS, CODE_BLOCKED_KEY_PREFIX))
                .thenReturn(true);
        var codeRequest = new VerifyMfaCodeRequest(MFAMethodType.AUTH_APP, CODE, false, JourneyType.REGISTRATION);
        var result = makeCallWithCode(codeRequest);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1042));
        assertThat(session.getVerifiedMfaMethodType(), equalTo(null));
        verify(codeStorageService, never())
                .saveBlockedForEmail(TEST_EMAIL_ADDRESS, CODE_BLOCKED_KEY_PREFIX, 900L);
        verify(authenticationService, never()).setAccountVerified(TEST_EMAIL_ADDRESS);
        verify(codeStorageService, never()).deleteIncorrectMfaCodeAttemptsCount(TEST_EMAIL_ADDRESS);
        verifyNoInteractions(accountRecoveryBlockService);
        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.CODE_MAX_RETRIES_REACHED,
                        CLIENT_SESSION_ID,
                        session.getSessionId(),
                        CLIENT_ID,
                        expectedCommonSubject,
                        TEST_EMAIL_ADDRESS,
                        "123.123.123.123",
                        AuditService.UNKNOWN,
                        PersistentIdHelper.PERSISTENT_ID_UNKNOWN_VALUE,
                        pair("mfa-type", MFAMethodType.AUTH_APP.getValue()));
    }

    @ParameterizedTest
    @MethodSource("registration")
    void shouldReturn400WhenUserEnteredInvalidAuthAppCode(boolean registration)
            throws Json.JsonException {
        when(mfaCodeValidatorFactory.getMfaCodeValidator(any(), any(JourneyType.class), any()))
                .thenReturn(Optional.of(authAppCodeValidator));
        var profileInformation = registration ? AUTH_APP_SECRET : null;
        when(authAppCodeValidator.validateCode(any(CodeRequest.class)))
                .thenReturn(Optional.of(ErrorResponse.ERROR_1043));
        var codeRequest =
                new VerifyMfaCodeRequest(MFAMethodType.AUTH_APP, CODE, false, JourneyType.REGISTRATION, profileInformation);
        var result = makeCallWithCode(codeRequest);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1043));
        assertThat(session.getVerifiedMfaMethodType(), equalTo(null));
        verify(codeStorageService, never())
                .saveBlockedForEmail(TEST_EMAIL_ADDRESS, CODE_BLOCKED_KEY_PREFIX, 900L);
        verify(authenticationService, never()).setAccountVerified(TEST_EMAIL_ADDRESS);
        verify(codeStorageService, never()).deleteIncorrectMfaCodeAttemptsCount(TEST_EMAIL_ADDRESS);
        verifyNoInteractions(accountRecoveryBlockService);
        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.INVALID_CODE_SENT,
                        CLIENT_SESSION_ID,
                        session.getSessionId(),
                        CLIENT_ID,
                        expectedCommonSubject,
                        TEST_EMAIL_ADDRESS,
                        "123.123.123.123",
                        AuditService.UNKNOWN,
                        PersistentIdHelper.PERSISTENT_ID_UNKNOWN_VALUE,
                        pair("mfa-type", MFAMethodType.AUTH_APP.getValue()));
    }

    @Test
    void
            shouldReturn400AndBlockCodeWhenUserEnteredInvalidPhoneNumberCodeDuringRegistrationTooManyTimes()
                    throws Json.JsonException {
        when(mfaCodeValidatorFactory.getMfaCodeValidator(any(), any(JourneyType.class), any()))
                .thenReturn(Optional.of(phoneNumberCodeValidator));
        when(phoneNumberCodeValidator.validateCode(any(CodeRequest.class)))
                .thenReturn(Optional.of(ErrorResponse.ERROR_1034));
        var codeRequest = new VerifyMfaCodeRequest(MFAMethodType.SMS, CODE, true, JourneyType.REGISTRATION, PHONE_NUMBER);
        var result = makeCallWithCode(codeRequest);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1034));
        assertThat(session.getVerifiedMfaMethodType(), equalTo(null));
        verify(codeStorageService)
                .saveBlockedForEmail(TEST_EMAIL_ADDRESS, CODE_BLOCKED_KEY_PREFIX, 900L);
        verify(authenticationService, never())
                .updatePhoneNumberAndAccountVerifiedStatus(
                        TEST_EMAIL_ADDRESS, PHONE_NUMBER, true, true);
        verify(authenticationService, never())
                .setMFAMethodEnabled(TEST_EMAIL_ADDRESS, MFAMethodType.AUTH_APP, false);
        verify(codeStorageService).deleteIncorrectMfaCodeAttemptsCount(TEST_EMAIL_ADDRESS);
        verifyNoInteractions(accountRecoveryBlockService);
        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.CODE_MAX_RETRIES_REACHED,
                        CLIENT_SESSION_ID,
                        session.getSessionId(),
                        CLIENT_ID,
                        expectedCommonSubject,
                        TEST_EMAIL_ADDRESS,
                        "123.123.123.123",
                        AuditService.UNKNOWN,
                        PersistentIdHelper.PERSISTENT_ID_UNKNOWN_VALUE,
                        pair("mfa-type", MFAMethodType.SMS.getValue()));
    }

    @Test
    void
            shouldReturn400AndNotBlockCodeWhenInvalidPhoneNumberCodeEnteredDuringRegistrationAndBlockAlreadyExists()
                    throws Json.JsonException {
        when(mfaCodeValidatorFactory.getMfaCodeValidator(any(), any(JourneyType.class), any()))
                .thenReturn(Optional.of(phoneNumberCodeValidator));
        when(phoneNumberCodeValidator.validateCode(any(CodeRequest.class)))
                .thenReturn(Optional.of(ErrorResponse.ERROR_1034));
        when(codeStorageService.isBlockedForEmail(TEST_EMAIL_ADDRESS, CODE_BLOCKED_KEY_PREFIX))
                .thenReturn(true);
        var codeRequest = new VerifyMfaCodeRequest(MFAMethodType.SMS, CODE, true, JourneyType.REGISTRATION, PHONE_NUMBER);
        var result = makeCallWithCode(codeRequest);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1034));
        assertThat(session.getVerifiedMfaMethodType(), equalTo(null));
        verify(codeStorageService, never())
                .saveBlockedForEmail(TEST_EMAIL_ADDRESS, CODE_BLOCKED_KEY_PREFIX, 900L);
        verify(authenticationService, never())
                .updatePhoneNumberAndAccountVerifiedStatus(
                        TEST_EMAIL_ADDRESS, PHONE_NUMBER, true, true);
        verify(authenticationService, never())
                .setMFAMethodEnabled(TEST_EMAIL_ADDRESS, MFAMethodType.AUTH_APP, false);
        verify(codeStorageService, never()).deleteIncorrectMfaCodeAttemptsCount(TEST_EMAIL_ADDRESS);
        verifyNoInteractions(accountRecoveryBlockService);
        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.CODE_MAX_RETRIES_REACHED,
                        CLIENT_SESSION_ID,
                        session.getSessionId(),
                        CLIENT_ID,
                        expectedCommonSubject,
                        TEST_EMAIL_ADDRESS,
                        "123.123.123.123",
                        AuditService.UNKNOWN,
                        PersistentIdHelper.PERSISTENT_ID_UNKNOWN_VALUE,
                        pair("mfa-type", MFAMethodType.SMS.getValue()));
    }

    @Test
    void shouldReturn400WhenUserEnteredInvalidPhoneNumberCodeForRegistration()
            throws Json.JsonException {
        when(mfaCodeValidatorFactory.getMfaCodeValidator(any(), any(JourneyType.class), any()))
                .thenReturn(Optional.of(phoneNumberCodeValidator));
        when(phoneNumberCodeValidator.validateCode(any(CodeRequest.class)))
                .thenReturn(Optional.of(ErrorResponse.ERROR_1037));
        var codeRequest = new VerifyMfaCodeRequest(MFAMethodType.SMS, CODE, true, JourneyType.REGISTRATION, PHONE_NUMBER);
        var result = makeCallWithCode(codeRequest);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1037));
        assertThat(session.getVerifiedMfaMethodType(), equalTo(null));
        verify(codeStorageService, never())
                .saveBlockedForEmail(TEST_EMAIL_ADDRESS, CODE_BLOCKED_KEY_PREFIX, 900L);
        verify(authenticationService, never())
                .updatePhoneNumberAndAccountVerifiedStatus(
                        TEST_EMAIL_ADDRESS, PHONE_NUMBER, true, true);
        verify(authenticationService, never())
                .setMFAMethodEnabled(TEST_EMAIL_ADDRESS, MFAMethodType.AUTH_APP, false);
        verify(codeStorageService, never()).deleteIncorrectMfaCodeAttemptsCount(TEST_EMAIL_ADDRESS);
        verifyNoInteractions(accountRecoveryBlockService);
        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.INVALID_CODE_SENT,
                        CLIENT_SESSION_ID,
                        session.getSessionId(),
                        CLIENT_ID,
                        expectedCommonSubject,
                        TEST_EMAIL_ADDRESS,
                        "123.123.123.123",
                        AuditService.UNKNOWN,
                        PersistentIdHelper.PERSISTENT_ID_UNKNOWN_VALUE,
                        pair("mfa-type", MFAMethodType.SMS.getValue()));
    }

    @Test
    void shouldReturn400WhenAuthAppSecretIsInvalid() throws Json.JsonException {
        when(mfaCodeValidatorFactory.getMfaCodeValidator(any(), any(JourneyType.class), any()))
                .thenReturn(Optional.of(authAppCodeValidator));
        when(authAppCodeValidator.validateCode(any(CodeRequest.class)))
                .thenReturn(Optional.of(ErrorResponse.ERROR_1041));
        session.setNewAccount(Session.AccountState.NEW);
        session.setCurrentCredentialStrength(CredentialTrustLevel.MEDIUM_LEVEL);
        var result =
                makeCallWithCode(
                        new VerifyMfaCodeRequest(
                                MFAMethodType.AUTH_APP, CODE, true, JourneyType.REGISTRATION, "not-base-32-encoded-secret"));

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1041));
        verify(authenticationService, never())
                .updateMFAMethod(
                        TEST_EMAIL_ADDRESS, MFAMethodType.AUTH_APP, true, true, AUTH_APP_SECRET);
        verify(authenticationService, never()).setAccountVerified(TEST_EMAIL_ADDRESS);
        verify(codeStorageService, never())
                .saveBlockedForEmail(TEST_EMAIL_ADDRESS, CODE_BLOCKED_KEY_PREFIX, 900L);
        verify(codeStorageService, never()).deleteIncorrectMfaCodeAttemptsCount(TEST_EMAIL_ADDRESS);
        verify(accountRecoveryBlockService, never()).deleteBlockIfPresent(TEST_EMAIL_ADDRESS);
        verifyNoInteractions(auditService);
        verifyNoInteractions(cloudwatchMetricsService);
    }

    private APIGatewayProxyResponseEvent makeCallWithCode(CodeRequest mfaCodeRequest)
            throws Json.JsonException {
        var event = new APIGatewayProxyRequestEvent();
        event.setRequestContext(contextWithSourceIp("123.123.123.123"));
        event.setHeaders(
                Map.of(
                        "Session-Id",
                        session.getSessionId(),
                        "Client-Session-Id",
                        CLIENT_SESSION_ID));
        event.setBody(objectMapper.writeValueAsString(mfaCodeRequest));
        when(sessionService.getSessionFromRequestHeaders(event.getHeaders()))
                .thenReturn(Optional.of(session));
        when(clientSessionService.getClientSessionFromRequestHeaders(event.getHeaders()))
                .thenReturn(Optional.of(clientSession));
        when(clientSessionService.getClientSessionFromRequestHeaders(event.getHeaders()))
                .thenReturn(Optional.of(clientSession));
        when(clientSession.getEffectiveVectorOfTrust()).thenReturn(VectorOfTrust.getDefaults());
        return handler.handleRequest(event, context);
    }

    private AuthenticationRequest withAuthenticationRequest() {
        return new AuthenticationRequest.Builder(
                        new ResponseType(ResponseType.Value.CODE),
                        new Scope(OIDCScopeValue.OPENID),
                        new ClientID(CLIENT_ID),
                        URI.create("https://redirectUri"))
                .state(new State())
                .nonce(new Nonce())
                .build();
    }
}
