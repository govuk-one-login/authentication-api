package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
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
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.entity.CodeRequest;
import uk.gov.di.authentication.entity.VerifyMfaCodeRequest;
import uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent;
import uk.gov.di.authentication.frontendapi.entity.ReauthFailureReasons;
import uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables;
import uk.gov.di.authentication.frontendapi.validation.AuthAppCodeProcessor;
import uk.gov.di.authentication.frontendapi.validation.MfaCodeProcessorFactory;
import uk.gov.di.authentication.frontendapi.validation.PhoneNumberCodeProcessor;
import uk.gov.di.authentication.shared.domain.AuditableEvent;
import uk.gov.di.authentication.shared.domain.CloudwatchMetrics;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.ClientSession;
import uk.gov.di.authentication.shared.entity.CodeRequestType;
import uk.gov.di.authentication.shared.entity.CountType;
import uk.gov.di.authentication.shared.entity.CredentialTrustLevel;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.helpers.SaltHelper;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthSessionService;
import uk.gov.di.authentication.shared.services.AuthenticationAttemptsService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.SerializationService;
import uk.gov.di.authentication.shared.services.SessionService;
import uk.gov.di.authentication.sharedtest.logging.CaptureLoggingExtension;

import java.net.URI;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Stream;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.not;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.frontendapi.helpers.ApiGatewayProxyRequestHelper.apiRequestEventWithHeadersAndBody;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.CLIENT_SESSION_ID;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.DI_PERSISTENT_SESSION_ID;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.EMAIL;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.ENCODED_DEVICE_DETAILS;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.INTERNAL_COMMON_SUBJECT_ID;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.IP_ADDRESS;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.SESSION_ID;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.VALID_HEADERS;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.VALID_HEADERS_WITHOUT_AUDIT_ENCODED;
import static uk.gov.di.authentication.shared.domain.CloudwatchMetricDimensions.ENVIRONMENT;
import static uk.gov.di.authentication.shared.domain.CloudwatchMetricDimensions.FAILURE_REASON;
import static uk.gov.di.authentication.shared.entity.CountType.ENTER_AUTH_APP_CODE;
import static uk.gov.di.authentication.shared.entity.CountType.ENTER_EMAIL;
import static uk.gov.di.authentication.shared.entity.CountType.ENTER_PASSWORD;
import static uk.gov.di.authentication.shared.entity.CountType.ENTER_SMS_CODE;
import static uk.gov.di.authentication.shared.entity.JourneyType.REAUTHENTICATION;
import static uk.gov.di.authentication.shared.services.AuditService.MetadataPair.pair;
import static uk.gov.di.authentication.shared.services.CodeStorageService.CODE_BLOCKED_KEY_PREFIX;
import static uk.gov.di.authentication.sharedtest.logging.LogEventMatcher.withMessageContaining;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class VerifyMfaCodeHandlerTest {

    private static final String CODE = "123456";
    private static final String CLIENT_ID = "client-id";
    private static final String CLIENT_NAME = "client-name";
    private static final String TEST_CLIENT_CODE = "654321";
    private static final String SUBJECT_ID = "test-subject-id";
    private static final String AUTH_APP_SECRET =
            "JZ5PYIOWNZDAOBA65S5T77FEEKYCCIT2VE4RQDAJD7SO73T3LODA";
    private static final String SECTOR_HOST = "test.account.gov.uk";
    private static final String CLIENT_SECTOR_HOST = "client.test.account.gov.uk";
    private static final byte[] SALT = SaltHelper.generateNewSalt();
    private static final String TEST_SUBJECT_ID = "test-subject-id";
    private static final int MAX_RETRIES = 6;

    private final String expectedRpPairwiseSubjectId =
            ClientSubjectHelper.calculatePairwiseIdentifier(
                    TEST_SUBJECT_ID, CLIENT_SECTOR_HOST, SALT);
    private final Session session = new Session();
    private final AuthSessionItem authSession =
            new AuthSessionItem()
                    .withSessionId(SESSION_ID)
                    .withEmailAddress(EMAIL)
                    .withInternalCommonSubjectId(INTERNAL_COMMON_SUBJECT_ID);
    private final Json objectMapper = SerializationService.getInstance();
    public VerifyMfaCodeHandler handler;

    private final Context context = mock(Context.class);
    private final SessionService sessionService = mock(SessionService.class);
    private final CodeStorageService codeStorageService = mock(CodeStorageService.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final MfaCodeProcessorFactory mfaCodeProcessorFactory =
            mock(MfaCodeProcessorFactory.class);
    private final AuthAppCodeProcessor authAppCodeProcessor = mock(AuthAppCodeProcessor.class);
    private final PhoneNumberCodeProcessor phoneNumberCodeProcessor =
            mock(PhoneNumberCodeProcessor.class);
    private final ClientSessionService clientSessionService = mock(ClientSessionService.class);
    private final ClientRegistry clientRegistry = mock(ClientRegistry.class);
    private final ClientService clientService = mock(ClientService.class);
    private final UserProfile userProfile = mock(UserProfile.class);
    private final AuthenticationService authenticationService = mock(AuthenticationService.class);
    private final ClientSession clientSession = mock(ClientSession.class);
    private final AuditService auditService = mock(AuditService.class);
    private final CloudwatchMetricsService cloudwatchMetricsService =
            mock(CloudwatchMetricsService.class);
    private final AuthenticationAttemptsService authenticationAttemptsService =
            mock(AuthenticationAttemptsService.class);
    private final AuthSessionService authSessionService = mock(AuthSessionService.class);

    @RegisterExtension
    private final CaptureLoggingExtension logging =
            new CaptureLoggingExtension(VerifyCodeHandler.class);

    private final AuditContext AUDIT_CONTEXT =
            new AuditContext(
                    CLIENT_ID,
                    CLIENT_SESSION_ID,
                    SESSION_ID,
                    INTERNAL_COMMON_SUBJECT_ID,
                    EMAIL,
                    IP_ADDRESS,
                    AuditService.UNKNOWN,
                    DI_PERSISTENT_SESSION_ID,
                    Optional.of(ENCODED_DEVICE_DETAILS));

    @BeforeEach
    void setUp() {
        when(authenticationService.getUserProfileFromEmail(EMAIL))
                .thenReturn(Optional.of(userProfile));
        when(clientService.getClient(CLIENT_ID)).thenReturn(Optional.of(clientRegistry));
        when(clientRegistry.getClientID()).thenReturn(CLIENT_ID);
        when(clientRegistry.getClientName()).thenReturn(CLIENT_NAME);
        when(userProfile.getSubjectID()).thenReturn(TEST_SUBJECT_ID);

        when(userProfile.getSubjectID()).thenReturn(SUBJECT_ID);
        when(configurationService.getEnvironment()).thenReturn("test");
        when(configurationService.getLockoutDuration()).thenReturn(900L);
        when(configurationService.getReducedLockoutDuration()).thenReturn(300L);
        when(configurationService.getCodeMaxRetries()).thenReturn(MAX_RETRIES);
        when(configurationService.getMaxPasswordRetries()).thenReturn(MAX_RETRIES);
        when(configurationService.getMaxEmailReAuthRetries()).thenReturn(MAX_RETRIES);
        when(clientSessionService.getClientSession(CLIENT_SESSION_ID))
                .thenReturn(Optional.of(clientSession));
        when(authSessionService.getSessionFromRequestHeaders(any()))
                .thenReturn(Optional.of(authSession));

        handler =
                new VerifyMfaCodeHandler(
                        configurationService,
                        sessionService,
                        clientSessionService,
                        clientService,
                        authenticationService,
                        codeStorageService,
                        auditService,
                        mfaCodeProcessorFactory,
                        cloudwatchMetricsService,
                        authenticationAttemptsService,
                        authSessionService);
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
                                        SESSION_ID,
                                        CLIENT_SESSION_ID))));
    }

    private static Stream<CredentialTrustLevel> credentialTrustLevels() {
        return Stream.of(CredentialTrustLevel.LOW_LEVEL, CredentialTrustLevel.MEDIUM_LEVEL);
    }

    @ParameterizedTest
    @MethodSource("credentialTrustLevels")
    void shouldReturn204WhenSuccessfulAuthAppCodeRegistrationRequest(
            CredentialTrustLevel credentialTrustLevel) throws Json.JsonException {
        when(mfaCodeProcessorFactory.getMfaCodeProcessor(any(), any(CodeRequest.class), any()))
                .thenReturn(Optional.of(authAppCodeProcessor));
        when(authAppCodeProcessor.validateCode()).thenReturn(Optional.empty());
        session.setCurrentCredentialStrength(credentialTrustLevel);
        authSession.setCurrentCredentialStrength(credentialTrustLevel);
        authSession.setIsNewAccount(AuthSessionItem.AccountState.NEW);
        var result =
                makeCallWithCode(
                        new VerifyMfaCodeRequest(
                                MFAMethodType.AUTH_APP,
                                CODE,
                                JourneyType.REGISTRATION,
                                AUTH_APP_SECRET));

        assertThat(result, hasStatus(204));
        assertThat(authSession.getVerifiedMfaMethodType(), equalTo(MFAMethodType.AUTH_APP));
        assertThat(
                authSession.getCurrentCredentialStrength(),
                equalTo(CredentialTrustLevel.MEDIUM_LEVEL));
        verify(authAppCodeProcessor).processSuccessfulCodeRequest(anyString(), anyString());
        verify(codeStorageService, never())
                .saveBlockedForEmail(EMAIL, CODE_BLOCKED_KEY_PREFIX, 900L);
        verify(codeStorageService, never()).deleteIncorrectMfaCodeAttemptsCount(EMAIL);

        assertAuditEventSubmittedWithMetadata(
                FrontendAuditableEvent.AUTH_CODE_VERIFIED,
                pair("mfa-type", MFAMethodType.AUTH_APP.getValue()),
                pair("account-recovery", false),
                pair("journey-type", JourneyType.REGISTRATION),
                pair("MFACodeEntered", CODE));
        verify(cloudwatchMetricsService)
                .incrementAuthenticationSuccess(
                        AuthSessionItem.AccountState.NEW,
                        CLIENT_ID,
                        CLIENT_NAME,
                        "P0",
                        false,
                        true);
    }

    @ParameterizedTest
    @MethodSource("credentialTrustLevels")
    void checkAuditEventStillEmittedWhenTICFHeaderNotProvided(
            CredentialTrustLevel credentialTrustLevel) throws Json.JsonException {
        when(mfaCodeProcessorFactory.getMfaCodeProcessor(any(), any(CodeRequest.class), any()))
                .thenReturn(Optional.of(authAppCodeProcessor));
        when(authAppCodeProcessor.validateCode()).thenReturn(Optional.empty());
        session.setCurrentCredentialStrength(credentialTrustLevel);
        authSession.setCurrentCredentialStrength(credentialTrustLevel);

        var mfaCodeRequest =
                new VerifyMfaCodeRequest(
                        MFAMethodType.AUTH_APP, CODE, JourneyType.REGISTRATION, AUTH_APP_SECRET);

        var body = objectMapper.writeValueAsString(mfaCodeRequest);
        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS_WITHOUT_AUDIT_ENCODED, body);
        when(sessionService.getSessionFromRequestHeaders(event.getHeaders()))
                .thenReturn(Optional.of(session));
        when(clientSessionService.getClientSessionFromRequestHeaders(event.getHeaders()))
                .thenReturn(Optional.of(clientSession));
        when(clientSessionService.getClientSessionFromRequestHeaders(event.getHeaders()))
                .thenReturn(Optional.of(clientSession));

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(204));
        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.AUTH_CODE_VERIFIED,
                        AUDIT_CONTEXT.withTxmaAuditEncoded(Optional.empty()),
                        pair("mfa-type", MFAMethodType.AUTH_APP.getValue()),
                        pair("account-recovery", false),
                        pair("journey-type", JourneyType.REGISTRATION),
                        pair("MFACodeEntered", CODE));
    }

    @ParameterizedTest
    @MethodSource("credentialTrustLevels")
    void shouldReturn204WhenSuccessfulAuthAppCodePasswordResetRequest(
            CredentialTrustLevel credentialTrustLevel) throws Json.JsonException {
        when(mfaCodeProcessorFactory.getMfaCodeProcessor(any(), any(CodeRequest.class), any()))
                .thenReturn(Optional.of(authAppCodeProcessor));
        when(authAppCodeProcessor.validateCode()).thenReturn(Optional.empty());
        when(configurationService.getInternalSectorUri()).thenReturn("http://" + SECTOR_HOST);
        when(authenticationService.getOrGenerateSalt(userProfile)).thenReturn(SALT);
        session.setCurrentCredentialStrength(credentialTrustLevel);
        authSession.setCurrentCredentialStrength(credentialTrustLevel);
        authSession.setIsNewAccount(AuthSessionItem.AccountState.EXISTING);

        var result =
                makeCallWithCode(
                        new VerifyMfaCodeRequest(
                                MFAMethodType.AUTH_APP,
                                CODE,
                                JourneyType.PASSWORD_RESET_MFA,
                                AUTH_APP_SECRET));

        assertThat(result, hasStatus(204));
        assertThat(authSession.getVerifiedMfaMethodType(), equalTo(MFAMethodType.AUTH_APP));
        assertThat(
                authSession.getCurrentCredentialStrength(),
                equalTo(CredentialTrustLevel.MEDIUM_LEVEL));
        verify(authAppCodeProcessor).processSuccessfulCodeRequest(anyString(), anyString());
        verify(codeStorageService, never())
                .saveBlockedForEmail(EMAIL, CODE_BLOCKED_KEY_PREFIX, 900L);
        verify(codeStorageService, never()).deleteIncorrectMfaCodeAttemptsCount(EMAIL);

        assertAuditEventSubmittedWithMetadata(
                FrontendAuditableEvent.AUTH_CODE_VERIFIED,
                pair("mfa-type", MFAMethodType.AUTH_APP.getValue()),
                pair("account-recovery", false),
                pair("journey-type", JourneyType.PASSWORD_RESET_MFA),
                pair("MFACodeEntered", CODE));
        verify(cloudwatchMetricsService)
                .incrementAuthenticationSuccess(
                        AuthSessionItem.AccountState.EXISTING,
                        CLIENT_ID,
                        CLIENT_NAME,
                        "P0",
                        false,
                        true);
    }

    @ParameterizedTest
    @MethodSource("credentialTrustLevels")
    void shouldReturn204WhenSuccessfulPhoneCodeRegistrationRequest(
            CredentialTrustLevel credentialTrustLevel) throws Json.JsonException {
        when(mfaCodeProcessorFactory.getMfaCodeProcessor(any(), any(CodeRequest.class), any()))
                .thenReturn(Optional.of(phoneNumberCodeProcessor));
        when(phoneNumberCodeProcessor.validateCode()).thenReturn(Optional.empty());
        authSession.setIsNewAccount(AuthSessionItem.AccountState.NEW);
        session.setCurrentCredentialStrength(credentialTrustLevel);
        authSession.setCurrentCredentialStrength(credentialTrustLevel);
        var result =
                makeCallWithCode(
                        new VerifyMfaCodeRequest(
                                MFAMethodType.SMS,
                                CODE,
                                JourneyType.REGISTRATION,
                                CommonTestVariables.UK_MOBILE_NUMBER));

        assertThat(result, hasStatus(204));
        assertThat(authSession.getVerifiedMfaMethodType(), equalTo(MFAMethodType.SMS));
        assertThat(
                authSession.getCurrentCredentialStrength(),
                equalTo(CredentialTrustLevel.MEDIUM_LEVEL));
        verify(phoneNumberCodeProcessor).processSuccessfulCodeRequest(anyString(), anyString());
        verify(codeStorageService, never())
                .saveBlockedForEmail(EMAIL, CODE_BLOCKED_KEY_PREFIX, 900L);
        verify(codeStorageService, never()).deleteIncorrectMfaCodeAttemptsCount(EMAIL);

        assertAuditEventSubmittedWithMetadata(
                FrontendAuditableEvent.AUTH_CODE_VERIFIED,
                pair("mfa-type", MFAMethodType.SMS.getValue()),
                pair("account-recovery", false),
                pair("journey-type", JourneyType.REGISTRATION),
                pair("MFACodeEntered", CODE));
        verify(cloudwatchMetricsService)
                .incrementAuthenticationSuccess(
                        AuthSessionItem.AccountState.NEW,
                        CLIENT_ID,
                        CLIENT_NAME,
                        "P0",
                        false,
                        true);
    }

    @ParameterizedTest
    @MethodSource("credentialTrustLevels")
    void shouldReturn204WhenSuccessfulAuthAppCodeForAccountRecovery(
            CredentialTrustLevel credentialTrustLevel) throws Json.JsonException {
        when(mfaCodeProcessorFactory.getMfaCodeProcessor(any(), any(CodeRequest.class), any()))
                .thenReturn(Optional.of(authAppCodeProcessor));
        when(authAppCodeProcessor.validateCode()).thenReturn(Optional.empty());
        authSession.setIsNewAccount(AuthSessionItem.AccountState.EXISTING);
        session.setCurrentCredentialStrength(credentialTrustLevel);
        authSession.setCurrentCredentialStrength(credentialTrustLevel);
        var result =
                makeCallWithCode(
                        new VerifyMfaCodeRequest(
                                MFAMethodType.AUTH_APP,
                                CODE,
                                JourneyType.ACCOUNT_RECOVERY,
                                AUTH_APP_SECRET));

        assertThat(result, hasStatus(204));
        assertThat(authSession.getVerifiedMfaMethodType(), equalTo(MFAMethodType.AUTH_APP));
        assertThat(
                authSession.getCurrentCredentialStrength(),
                equalTo(CredentialTrustLevel.MEDIUM_LEVEL));
        verify(authAppCodeProcessor).processSuccessfulCodeRequest(anyString(), anyString());
        verify(codeStorageService, never())
                .saveBlockedForEmail(EMAIL, CODE_BLOCKED_KEY_PREFIX, 900L);
        verify(codeStorageService, never()).deleteIncorrectMfaCodeAttemptsCount(EMAIL);

        assertAuditEventSubmittedWithMetadata(
                FrontendAuditableEvent.AUTH_CODE_VERIFIED,
                pair("mfa-type", MFAMethodType.AUTH_APP.getValue()),
                pair("account-recovery", true),
                pair("journey-type", JourneyType.ACCOUNT_RECOVERY),
                pair("MFACodeEntered", CODE));
        verify(cloudwatchMetricsService)
                .incrementAuthenticationSuccess(
                        AuthSessionItem.AccountState.EXISTING,
                        CLIENT_ID,
                        CLIENT_NAME,
                        "P0",
                        false,
                        true);
        verify(authSessionService, times(2))
                .updateSession(
                        argThat(
                                state ->
                                        state.getResetMfaState()
                                                .equals(AuthSessionItem.ResetMfaState.SUCCEEDED)));
    }

    @ParameterizedTest
    @MethodSource("credentialTrustLevels")
    void shouldReturn204WhenSuccessfulSMSCodeForAccountRecovery(
            CredentialTrustLevel credentialTrustLevel) throws Json.JsonException {
        when(mfaCodeProcessorFactory.getMfaCodeProcessor(any(), any(CodeRequest.class), any()))
                .thenReturn(Optional.of(authAppCodeProcessor));
        when(authAppCodeProcessor.validateCode()).thenReturn(Optional.empty());
        authSession.setIsNewAccount(AuthSessionItem.AccountState.EXISTING);
        session.setCurrentCredentialStrength(credentialTrustLevel);
        authSession.setCurrentCredentialStrength(credentialTrustLevel);
        var result =
                makeCallWithCode(
                        new VerifyMfaCodeRequest(
                                MFAMethodType.SMS,
                                CODE,
                                JourneyType.ACCOUNT_RECOVERY,
                                CommonTestVariables.UK_MOBILE_NUMBER));

        assertThat(result, hasStatus(204));
        assertThat(authSession.getVerifiedMfaMethodType(), equalTo(MFAMethodType.SMS));
        assertThat(
                authSession.getCurrentCredentialStrength(),
                equalTo(CredentialTrustLevel.MEDIUM_LEVEL));
        verify(authAppCodeProcessor).processSuccessfulCodeRequest(anyString(), anyString());
        verify(codeStorageService, never())
                .saveBlockedForEmail(EMAIL, CODE_BLOCKED_KEY_PREFIX, 900L);
        verify(codeStorageService, never()).deleteIncorrectMfaCodeAttemptsCount(EMAIL);

        assertAuditEventSubmittedWithMetadata(
                FrontendAuditableEvent.AUTH_CODE_VERIFIED,
                pair("mfa-type", MFAMethodType.SMS.getValue()),
                pair("account-recovery", true),
                pair("journey-type", JourneyType.ACCOUNT_RECOVERY),
                pair("MFACodeEntered", CODE));
        verify(cloudwatchMetricsService)
                .incrementAuthenticationSuccess(
                        AuthSessionItem.AccountState.EXISTING,
                        CLIENT_ID,
                        CLIENT_NAME,
                        "P0",
                        false,
                        true);
        verify(authSessionService, times(2))
                .updateSession(
                        argThat(
                                state ->
                                        state.getResetMfaState()
                                                .equals(AuthSessionItem.ResetMfaState.SUCCEEDED)));
    }

    private static Stream<JourneyType> existingUserAuthAppJourneyTypes() {
        return Stream.of(JourneyType.SIGN_IN, JourneyType.PASSWORD_RESET_MFA, REAUTHENTICATION);
    }

    @ParameterizedTest
    @MethodSource("existingUserAuthAppJourneyTypes")
    void shouldReturn204WhenExistingUserSuccessfulAuthAppCodeRequest(JourneyType journeyType)
            throws Json.JsonException {
        when(mfaCodeProcessorFactory.getMfaCodeProcessor(any(), any(CodeRequest.class), any()))
                .thenReturn(Optional.of(authAppCodeProcessor));
        when(authAppCodeProcessor.validateCode()).thenReturn(Optional.empty());
        authSession.setIsNewAccount(AuthSessionItem.AccountState.EXISTING);
        var codeRequest = new VerifyMfaCodeRequest(MFAMethodType.AUTH_APP, CODE, journeyType);
        var result = makeCallWithCode(codeRequest);

        assertThat(result, hasStatus(204));
        assertThat(authSession.getVerifiedMfaMethodType(), equalTo(MFAMethodType.AUTH_APP));
        verify(codeStorageService, never())
                .saveBlockedForEmail(EMAIL, CODE_BLOCKED_KEY_PREFIX, 900L);
        verify(codeStorageService, never()).deleteIncorrectMfaCodeAttemptsCount(EMAIL);
        assertAuditEventSubmittedWithMetadata(
                FrontendAuditableEvent.AUTH_CODE_VERIFIED,
                pair("mfa-type", MFAMethodType.AUTH_APP.getValue()),
                pair("account-recovery", false),
                pair("journey-type", journeyType),
                pair("MFACodeEntered", CODE));
        verify(cloudwatchMetricsService)
                .incrementAuthenticationSuccess(
                        AuthSessionItem.AccountState.EXISTING,
                        CLIENT_ID,
                        CLIENT_NAME,
                        "P0",
                        false,
                        true);
    }

    @ParameterizedTest
    @EnumSource(JourneyType.class)
    void shouldReturn400IfMfaCodeProcessorCannotBeFound(JourneyType journeyType)
            throws Json.JsonException {
        when(mfaCodeProcessorFactory.getMfaCodeProcessor(any(), any(CodeRequest.class), any()))
                .thenReturn(Optional.empty());
        var authAppSecret =
                List.of(JourneyType.SIGN_IN, JourneyType.PASSWORD_RESET_MFA, REAUTHENTICATION)
                                .contains(journeyType)
                        ? null
                        : AUTH_APP_SECRET;
        var codeRequest =
                new VerifyMfaCodeRequest(MFAMethodType.AUTH_APP, CODE, journeyType, authAppSecret);
        var result = makeCallWithCode(codeRequest);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1002));
        assertThat(authSession.getVerifiedMfaMethodType(), equalTo(null));
        verifyNoInteractions(auditService);
        verifyNoInteractions(authAppCodeProcessor);
        verifyNoInteractions(codeStorageService);
        verifyNoInteractions(cloudwatchMetricsService);
    }

    @ParameterizedTest
    @EnumSource(JourneyType.class)
    void shouldReturn400IfPhoneCodeProcessorCannotBeFound(JourneyType journeyType)
            throws Json.JsonException {
        when(mfaCodeProcessorFactory.getMfaCodeProcessor(any(), any(CodeRequest.class), any()))
                .thenReturn(Optional.empty());
        var phoneNumber =
                List.of(JourneyType.SIGN_IN, JourneyType.PASSWORD_RESET_MFA).contains(journeyType)
                        ? null
                        : CommonTestVariables.UK_MOBILE_NUMBER;
        var codeRequest =
                new VerifyMfaCodeRequest(MFAMethodType.SMS, CODE, journeyType, phoneNumber);
        var result = makeCallWithCode(codeRequest);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1002));
        assertThat(authSession.getVerifiedMfaMethodType(), equalTo(null));
        verifyNoInteractions(auditService);
        verifyNoInteractions(authAppCodeProcessor);
        verifyNoInteractions(codeStorageService);
        verifyNoInteractions(cloudwatchMetricsService);
    }

    private static Stream<Arguments> blockedCodeForAuthAppOTPEnteredTooManyTimes() {
        return Stream.of(
                Arguments.of(
                        JourneyType.ACCOUNT_RECOVERY, CodeRequestType.AUTH_APP_ACCOUNT_RECOVERY),
                Arguments.of(JourneyType.REGISTRATION, CodeRequestType.AUTH_APP_REGISTRATION),
                Arguments.of(JourneyType.SIGN_IN, CodeRequestType.AUTH_APP_SIGN_IN),
                Arguments.of(JourneyType.PASSWORD_RESET_MFA, CodeRequestType.PW_RESET_MFA_AUTH_APP),
                Arguments.of(REAUTHENTICATION, CodeRequestType.AUTH_APP_REAUTHENTICATION));
    }

    @ParameterizedTest
    @MethodSource("blockedCodeForAuthAppOTPEnteredTooManyTimes")
    void shouldReturn400AndBlockCodeWhenUserEnteredInvalidAuthAppCodeTooManyTimes(
            JourneyType journeyType, CodeRequestType codeRequestType) throws Json.JsonException {
        withReauthTurnedOn();
        when(mfaCodeProcessorFactory.getMfaCodeProcessor(any(), any(CodeRequest.class), any()))
                .thenReturn(Optional.of(authAppCodeProcessor));
        when(authAppCodeProcessor.validateCode()).thenReturn(Optional.of(ErrorResponse.ERROR_1042));
        var authAppSecret =
                List.of(JourneyType.SIGN_IN, JourneyType.PASSWORD_RESET_MFA).contains(journeyType)
                        ? null
                        : AUTH_APP_SECRET;
        var codeRequest =
                new VerifyMfaCodeRequest(MFAMethodType.AUTH_APP, CODE, journeyType, authAppSecret);
        var result = makeCallWithCode(codeRequest);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1042));
        assertThat(authSession.getVerifiedMfaMethodType(), equalTo(null));
        if (journeyType != REAUTHENTICATION) {
            verify(codeStorageService)
                    .saveBlockedForEmail(EMAIL, CODE_BLOCKED_KEY_PREFIX + codeRequestType, 900L);
            verifyNoInteractions(authenticationAttemptsService);
        }
        verify(codeStorageService)
                .deleteIncorrectMfaCodeAttemptsCount(EMAIL, MFAMethodType.AUTH_APP);
        verifyNoInteractions(cloudwatchMetricsService);
        assertAuditEventSubmittedWithMetadata(
                FrontendAuditableEvent.AUTH_CODE_MAX_RETRIES_REACHED,
                pair("mfa-type", MFAMethodType.AUTH_APP.getValue()),
                pair("account-recovery", journeyType.equals(JourneyType.ACCOUNT_RECOVERY)),
                pair("journey-type", journeyType),
                pair("attemptNoFailedAt", configurationService.getCodeMaxRetries()));
    }

    @ParameterizedTest
    @EnumSource(JourneyType.class)
    void shouldReturn400AndNotBlockCodeWhenUserEnteredInvalidAuthAppCodeAndBlockAlreadyExists(
            JourneyType journeyType) throws Json.JsonException {
        when(mfaCodeProcessorFactory.getMfaCodeProcessor(any(), any(CodeRequest.class), any()))
                .thenReturn(Optional.of(authAppCodeProcessor));
        when(authAppCodeProcessor.validateCode()).thenReturn(Optional.of(ErrorResponse.ERROR_1042));
        when(codeStorageService.isBlockedForEmail(EMAIL, CODE_BLOCKED_KEY_PREFIX)).thenReturn(true);
        var authAppSecret =
                List.of(JourneyType.SIGN_IN, JourneyType.PASSWORD_RESET_MFA).contains(journeyType)
                        ? null
                        : AUTH_APP_SECRET;
        var codeRequest =
                new VerifyMfaCodeRequest(MFAMethodType.AUTH_APP, CODE, journeyType, authAppSecret);

        if (!CodeRequestType.isValidCodeRequestType(
                codeRequest.getMfaMethodType(), codeRequest.getJourneyType())) {
            return;
        }

        var result = makeCallWithCode(codeRequest);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1042));
        assertThat(authSession.getVerifiedMfaMethodType(), equalTo(null));
        verify(codeStorageService, never())
                .saveBlockedForEmail(EMAIL, CODE_BLOCKED_KEY_PREFIX, 900L);
        verify(codeStorageService, never()).deleteIncorrectMfaCodeAttemptsCount(EMAIL);
        verifyNoInteractions(cloudwatchMetricsService);
        verifyNoInteractions(authenticationAttemptsService);
        assertAuditEventSubmittedWithMetadata(
                FrontendAuditableEvent.AUTH_CODE_MAX_RETRIES_REACHED,
                pair("mfa-type", MFAMethodType.AUTH_APP.getValue()),
                pair("account-recovery", journeyType.equals(JourneyType.ACCOUNT_RECOVERY)),
                pair("journey-type", journeyType),
                pair("attemptNoFailedAt", configurationService.getCodeMaxRetries()));
    }

    @ParameterizedTest
    @EnumSource(JourneyType.class)
    void shouldReturn400WhenUserEnteredInvalidAuthAppOtpCode(JourneyType journeyType)
            throws Json.JsonException {
        when(mfaCodeProcessorFactory.getMfaCodeProcessor(any(), any(CodeRequest.class), any()))
                .thenReturn(Optional.of(authAppCodeProcessor));
        var profileInformation =
                List.of(JourneyType.SIGN_IN, JourneyType.PASSWORD_RESET_MFA, REAUTHENTICATION)
                                .contains(journeyType)
                        ? null
                        : AUTH_APP_SECRET;
        when(authAppCodeProcessor.validateCode()).thenReturn(Optional.of(ErrorResponse.ERROR_1043));
        when(codeStorageService.getIncorrectMfaCodeAttemptsCount(EMAIL, MFAMethodType.AUTH_APP))
                .thenReturn(3);
        var codeRequest =
                new VerifyMfaCodeRequest(
                        MFAMethodType.AUTH_APP, CODE, journeyType, profileInformation);
        if (!CodeRequestType.isValidCodeRequestType(
                codeRequest.getMfaMethodType(), codeRequest.getJourneyType())) {
            return;
        }
        var result = makeCallWithCode(codeRequest);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1043));
        assertThat(authSession.getVerifiedMfaMethodType(), equalTo(null));
        verify(codeStorageService, never())
                .saveBlockedForEmail(EMAIL, CODE_BLOCKED_KEY_PREFIX, 900L);
        verify(codeStorageService, never()).deleteIncorrectMfaCodeAttemptsCount(EMAIL);
        verifyNoInteractions(cloudwatchMetricsService);
        verifyNoInteractions(authenticationAttemptsService);
        assertAuditEventSubmittedWithMetadata(
                FrontendAuditableEvent.AUTH_INVALID_CODE_SENT,
                pair("mfa-type", MFAMethodType.AUTH_APP.getValue()),
                pair("account-recovery", journeyType.equals(JourneyType.ACCOUNT_RECOVERY)),
                pair("journey-type", journeyType),
                pair("loginFailureCount", 3),
                pair("MFACodeEntered", CODE));
    }

    private static Stream<Arguments> blockedCodeForInvalidPhoneNumberTooManyTimes() {
        return Stream.of(
                Arguments.of(JourneyType.ACCOUNT_RECOVERY, CodeRequestType.SMS_ACCOUNT_RECOVERY),
                Arguments.of(JourneyType.PASSWORD_RESET_MFA, CodeRequestType.PW_RESET_MFA_SMS),
                Arguments.of(JourneyType.REGISTRATION, CodeRequestType.SMS_REGISTRATION),
                Arguments.of(REAUTHENTICATION, CodeRequestType.SMS_REAUTHENTICATION));
    }

    @ParameterizedTest
    @MethodSource("blockedCodeForInvalidPhoneNumberTooManyTimes")
    void shouldReturn400AndBlockCodeWhenUserEnteredInvalidPhoneNumberCodeTooManyTimes(
            JourneyType journeyType, CodeRequestType codeRequestType) throws Json.JsonException {
        withReauthTurnedOn();
        when(mfaCodeProcessorFactory.getMfaCodeProcessor(any(), any(CodeRequest.class), any()))
                .thenReturn(Optional.of(phoneNumberCodeProcessor));
        when(phoneNumberCodeProcessor.validateCode())
                .thenReturn(Optional.of(ErrorResponse.ERROR_1034));
        var codeRequest =
                new VerifyMfaCodeRequest(
                        MFAMethodType.SMS, CODE, journeyType, CommonTestVariables.UK_MOBILE_NUMBER);
        var result = makeCallWithCode(codeRequest);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1034));
        assertThat(authSession.getVerifiedMfaMethodType(), equalTo(null));
        long blockTime = 900L;
        if (List.of(CodeRequestType.SMS_REGISTRATION, CodeRequestType.SMS_ACCOUNT_RECOVERY)
                .contains(codeRequestType)) {
            blockTime = 300L;
        }
        if (journeyType != REAUTHENTICATION) {
            verify(codeStorageService)
                    .saveBlockedForEmail(
                            EMAIL, CODE_BLOCKED_KEY_PREFIX + codeRequestType, blockTime);
        }
        verify(codeStorageService).deleteIncorrectMfaCodeAttemptsCount(EMAIL);
        verifyNoInteractions(cloudwatchMetricsService);
        assertAuditEventSubmittedWithMetadata(
                FrontendAuditableEvent.AUTH_CODE_MAX_RETRIES_REACHED,
                pair("mfa-type", MFAMethodType.SMS.getValue()),
                pair("account-recovery", journeyType.equals(JourneyType.ACCOUNT_RECOVERY)),
                pair("journey-type", journeyType),
                pair("attemptNoFailedAt", configurationService.getCodeMaxRetries()));
    }

    @ParameterizedTest
    @MethodSource("blockedCodeForInvalidPhoneNumberTooManyTimes")
    void shouldReturn400AndNotBlockCodeWhenInvalidPhoneNumberCodeEnteredAndBlockAlreadyExists(
            JourneyType journeyType, CodeRequestType codeRequestType) throws Json.JsonException {
        when(mfaCodeProcessorFactory.getMfaCodeProcessor(any(), any(CodeRequest.class), any()))
                .thenReturn(Optional.of(phoneNumberCodeProcessor));
        when(phoneNumberCodeProcessor.validateCode())
                .thenReturn(Optional.of(ErrorResponse.ERROR_1034));
        var codeBlockedPrefix = CODE_BLOCKED_KEY_PREFIX + codeRequestType;
        when(codeStorageService.isBlockedForEmail(EMAIL, codeBlockedPrefix)).thenReturn(true);
        var codeRequest =
                new VerifyMfaCodeRequest(
                        MFAMethodType.SMS, CODE, journeyType, CommonTestVariables.UK_MOBILE_NUMBER);
        var result = makeCallWithCode(codeRequest);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1034));
        assertThat(authSession.getVerifiedMfaMethodType(), equalTo(null));
        verify(codeStorageService, never()).saveBlockedForEmail(EMAIL, codeBlockedPrefix, 900L);
        verify(codeStorageService, never()).deleteIncorrectMfaCodeAttemptsCount(EMAIL);
        verifyNoInteractions(cloudwatchMetricsService);
        assertAuditEventSubmittedWithMetadata(
                FrontendAuditableEvent.AUTH_CODE_MAX_RETRIES_REACHED,
                pair("mfa-type", MFAMethodType.SMS.getValue()),
                pair("account-recovery", journeyType.equals(JourneyType.ACCOUNT_RECOVERY)),
                pair("journey-type", journeyType),
                pair("attemptNoFailedAt", configurationService.getCodeMaxRetries()));
    }

    @ParameterizedTest
    @EnumSource(
            value = JourneyType.class,
            names = {"SIGN_IN"},
            mode = EnumSource.Mode.EXCLUDE)
    void shouldReturn400WhenUserEnteredInvalidPhoneNumberOtpCode(JourneyType journeyType)
            throws Json.JsonException {
        when(mfaCodeProcessorFactory.getMfaCodeProcessor(any(), any(CodeRequest.class), any()))
                .thenReturn(Optional.of(phoneNumberCodeProcessor));
        when(phoneNumberCodeProcessor.validateCode())
                .thenReturn(Optional.of(ErrorResponse.ERROR_1037));
        when(codeStorageService.getIncorrectMfaCodeAttemptsCount(EMAIL)).thenReturn(3);
        var codeRequest =
                new VerifyMfaCodeRequest(
                        MFAMethodType.SMS, CODE, journeyType, CommonTestVariables.UK_MOBILE_NUMBER);
        if (!CodeRequestType.isValidCodeRequestType(
                codeRequest.getMfaMethodType(), codeRequest.getJourneyType())) {
            return;
        }
        var result = makeCallWithCode(codeRequest);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1037));
        assertThat(authSession.getVerifiedMfaMethodType(), equalTo(null));
        verify(codeStorageService, never())
                .saveBlockedForEmail(EMAIL, CODE_BLOCKED_KEY_PREFIX, 900L);
        verify(codeStorageService, never()).deleteIncorrectMfaCodeAttemptsCount(EMAIL);
        verifyNoInteractions(cloudwatchMetricsService);
        assertAuditEventSubmittedWithMetadata(
                FrontendAuditableEvent.AUTH_INVALID_CODE_SENT,
                pair("mfa-type", MFAMethodType.SMS.getValue()),
                pair("account-recovery", journeyType.equals(JourneyType.ACCOUNT_RECOVERY)),
                pair("journey-type", journeyType),
                pair("loginFailureCount", 3),
                pair("MFACodeEntered", CODE));
    }

    @ParameterizedTest
    @EnumSource(
            value = JourneyType.class,
            names = {"SIGN_IN"},
            mode = EnumSource.Mode.EXCLUDE)
    void shouldReturn400WhenAuthAppSecretIsInvalid(JourneyType journeyType)
            throws Json.JsonException {
        when(mfaCodeProcessorFactory.getMfaCodeProcessor(any(), any(CodeRequest.class), any()))
                .thenReturn(Optional.of(authAppCodeProcessor));
        when(authAppCodeProcessor.validateCode()).thenReturn(Optional.of(ErrorResponse.ERROR_1041));
        session.setCurrentCredentialStrength(CredentialTrustLevel.MEDIUM_LEVEL);
        if (!CodeRequestType.isValidCodeRequestType(MFAMethodType.AUTH_APP, journeyType)) {
            return;
        }
        var result =
                makeCallWithCode(
                        new VerifyMfaCodeRequest(
                                MFAMethodType.AUTH_APP,
                                CODE,
                                journeyType,
                                "not-base-32-encoded-secret"));

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1041));
        verify(codeStorageService, never())
                .saveBlockedForEmail(EMAIL, CODE_BLOCKED_KEY_PREFIX, 900L);
        verify(codeStorageService, never()).deleteIncorrectMfaCodeAttemptsCount(EMAIL);
        verifyNoInteractions(auditService);
        verifyNoInteractions(cloudwatchMetricsService);
    }

    @Test
    void shouldIncrementAuthAppAuthenticationAttemptsCountIfIncorrectCodeEntered()
            throws Json.JsonException {
        long ttl = 3600L;
        when(mfaCodeProcessorFactory.getMfaCodeProcessor(any(), any(CodeRequest.class), any()))
                .thenReturn(Optional.of(authAppCodeProcessor));
        withReauthTurnedOn();
        when(authAppCodeProcessor.validateCode()).thenReturn(Optional.of(ErrorResponse.ERROR_1043));
        when(configurationService.getReauthEnterAuthAppCodeCountTTL()).thenReturn(ttl);
        MockedStatic<NowHelper> mockedNowHelperClass = mockStatic(NowHelper.class);
        mockedNowHelperClass
                .when(() -> NowHelper.nowPlus(ttl, ChronoUnit.SECONDS))
                .thenReturn(Date.from(Instant.parse("2024-01-01T00:00:00.00Z")));

        var codeRequest =
                new VerifyMfaCodeRequest(MFAMethodType.AUTH_APP, CODE, REAUTHENTICATION, null);
        makeCallWithCode(codeRequest);

        verify(authenticationAttemptsService, times(1))
                .createOrIncrementCount(
                        TEST_SUBJECT_ID,
                        1704067200L,
                        REAUTHENTICATION,
                        CountType.ENTER_AUTH_APP_CODE);

        mockedNowHelperClass.close();
    }

    @Test
    void
            shouldDeleteAuthAppAuthenticationAttemptsCountAndStoreCountsInSessionIfCorrectCodeEnteredForReauthJourney()
                    throws Json.JsonException {
        when(mfaCodeProcessorFactory.getMfaCodeProcessor(any(), any(CodeRequest.class), any()))
                .thenReturn(Optional.of(authAppCodeProcessor));
        withReauthTurnedOn();
        when(authAppCodeProcessor.validateCode()).thenReturn(Optional.empty());

        var existingCounts = Map.of(CountType.ENTER_PASSWORD, 5, CountType.ENTER_AUTH_APP_CODE, 4);
        when(authenticationAttemptsService.getCountsByJourneyForSubjectIdAndRpPairwiseId(
                        eq(SUBJECT_ID), any(), eq(JourneyType.REAUTHENTICATION)))
                .thenReturn(existingCounts);
        when(clientRegistry.getSectorIdentifierUri()).thenReturn("http://" + CLIENT_SECTOR_HOST);
        when(authenticationService.getOrGenerateSalt(userProfile)).thenReturn(SALT);

        var codeRequest =
                new VerifyMfaCodeRequest(
                        MFAMethodType.AUTH_APP, CODE, JourneyType.REAUTHENTICATION, null);
        makeCallWithCode(codeRequest);

        List.of(TEST_SUBJECT_ID, expectedRpPairwiseSubjectId)
                .forEach(
                        identifier ->
                                verify(
                                                authenticationAttemptsService,
                                                times(CountType.values().length))
                                        .deleteCount(
                                                eq(identifier),
                                                eq(JourneyType.REAUTHENTICATION),
                                                any()));

        verify(authSessionService, atLeastOnce())
                .updateSession(
                        argThat(
                                s ->
                                        s.getPreservedReauthCountsForAuditMap()
                                                .equals(existingCounts)));
    }

    @Test
    void
            shouldDeleteAuthAppAuthenticationAttemptsCountAndNotStoreCountsInSessionIfCorrectCodeEnteredForSigninJourney()
                    throws Json.JsonException {
        when(mfaCodeProcessorFactory.getMfaCodeProcessor(any(), any(CodeRequest.class), any()))
                .thenReturn(Optional.of(authAppCodeProcessor));
        withReauthTurnedOn();
        when(authAppCodeProcessor.validateCode()).thenReturn(Optional.empty());

        var existingCounts = Map.of(CountType.ENTER_PASSWORD, 5, CountType.ENTER_AUTH_APP_CODE, 4);
        when(authenticationAttemptsService.getCountsByJourneyForSubjectIdAndRpPairwiseId(
                        eq(SUBJECT_ID), any(), eq(JourneyType.REAUTHENTICATION)))
                .thenReturn(existingCounts);

        var codeRequest =
                new VerifyMfaCodeRequest(MFAMethodType.AUTH_APP, CODE, JourneyType.SIGN_IN, null);
        makeCallWithCode(codeRequest);

        verify(authenticationAttemptsService, times(1))
                .deleteCount(
                        TEST_SUBJECT_ID,
                        JourneyType.REAUTHENTICATION,
                        CountType.ENTER_AUTH_APP_CODE);

        verify(authSessionService, never())
                .updateSession(
                        argThat(
                                s ->
                                        Objects.equals(
                                                s.getPreservedReauthCountsForAuditMap(),
                                                existingCounts)));
    }

    @Test
    void shouldReturn400AndThrowClientNotFoundExceptionIfNoClientIsPresent()
            throws Json.JsonException {
        when(clientService.getClient(CLIENT_ID)).thenReturn(Optional.empty());

        var result =
                makeCallWithCode(
                        new VerifyMfaCodeRequest(
                                MFAMethodType.AUTH_APP,
                                CODE,
                                JourneyType.REGISTRATION,
                                AUTH_APP_SECRET));

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1015));
    }

    private static Stream<Arguments> reauthCountTypesAndMetadata() {
        return Stream.of(
                Arguments.arguments(
                        ENTER_EMAIL,
                        MAX_RETRIES,
                        0,
                        0,
                        ReauthFailureReasons.INCORRECT_EMAIL.getValue()),
                Arguments.arguments(
                        ENTER_PASSWORD,
                        0,
                        MAX_RETRIES,
                        0,
                        ReauthFailureReasons.INCORRECT_PASSWORD.getValue()),
                Arguments.arguments(
                        ENTER_SMS_CODE,
                        0,
                        0,
                        MAX_RETRIES,
                        ReauthFailureReasons.INCORRECT_OTP.getValue()),
                Arguments.arguments(
                        ENTER_AUTH_APP_CODE,
                        0,
                        0,
                        MAX_RETRIES,
                        ReauthFailureReasons.INCORRECT_OTP.getValue()));
    }

    @ParameterizedTest
    @MethodSource("reauthCountTypesAndMetadata")
    void shouldReturnErrorIfUserHasTooManyReauthAttemptCountsOfAnyType(
            CountType countType,
            int expectedEmailAttemptCount,
            int expectedPasswordAttemptCount,
            int expectedOtpAttemptCount,
            String expectedFailureReason)
            throws Json.JsonException {
        try (MockedStatic<ClientSubjectHelper> mockedClientSubjectHelperClass =
                Mockito.mockStatic(ClientSubjectHelper.class, Mockito.CALLS_REAL_METHODS)) {
            when(configurationService.isAuthenticationAttemptsServiceEnabled()).thenReturn(true);
            when(authenticationAttemptsService.getCountsByJourneyForSubjectIdAndRpPairwiseId(
                            any(), any(), eq(REAUTHENTICATION)))
                    .thenReturn(Map.of(countType, MAX_RETRIES));
            when(configurationService.getInternalSectorUri())
                    .thenReturn("https://test.account.gov.uk");
            Subject subject = new Subject(TEST_SUBJECT_ID);
            mockedClientSubjectHelperClass
                    .when(
                            () ->
                                    ClientSubjectHelper.getSubject(
                                            eq(userProfile),
                                            any(ClientRegistry.class),
                                            any(AuthenticationService.class),
                                            any(String.class)))
                    .thenReturn(subject);

            var codeRequest =
                    new VerifyMfaCodeRequest(MFAMethodType.AUTH_APP, CODE, REAUTHENTICATION, null);
            var result = makeCallWithCode(codeRequest);

            verify(auditService, times(1))
                    .submitAuditEvent(
                            FrontendAuditableEvent.AUTH_REAUTH_FAILED,
                            AUDIT_CONTEXT,
                            pair("rpPairwiseId", subject.getValue()),
                            pair("incorrect_email_attempt_count", expectedEmailAttemptCount),
                            pair("incorrect_password_attempt_count", expectedPasswordAttemptCount),
                            pair("incorrect_otp_code_attempt_count", expectedOtpAttemptCount),
                            pair("failure-reason", expectedFailureReason));
            verify(cloudwatchMetricsService)
                    .incrementCounter(
                            CloudwatchMetrics.REAUTH_FAILED.getValue(),
                            Map.of(
                                    ENVIRONMENT.getValue(),
                                    configurationService.getEnvironment(),
                                    FAILURE_REASON.getValue(),
                                    expectedFailureReason));

            assertThat(result, hasStatus(400));
            assertThat(result, hasJsonBody(ErrorResponse.ERROR_1057));
        }
    }

    private APIGatewayProxyResponseEvent makeCallWithCode(CodeRequest mfaCodeRequest)
            throws Json.JsonException {
        var body = objectMapper.writeValueAsString(mfaCodeRequest);
        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, body);
        when(sessionService.getSessionFromRequestHeaders(event.getHeaders()))
                .thenReturn(Optional.of(session));
        when(clientSessionService.getClientSessionFromRequestHeaders(event.getHeaders()))
                .thenReturn(Optional.of(clientSession));
        when(clientSessionService.getClientSessionFromRequestHeaders(event.getHeaders()))
                .thenReturn(Optional.of(clientSession));
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

    private void assertAuditEventSubmittedWithMetadata(
            AuditableEvent event, AuditService.MetadataPair... pairs) {
        verify(auditService).submitAuditEvent(event, AUDIT_CONTEXT, pairs);
    }

    private void withReauthTurnedOn() {
        when(configurationService.isAuthenticationAttemptsServiceEnabled()).thenReturn(true);
        when(configurationService.supportReauthSignoutEnabled()).thenReturn(true);
    }
}
