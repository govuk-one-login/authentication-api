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
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent;
import uk.gov.di.authentication.frontendapi.entity.ReauthFailureReasons;
import uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables;
import uk.gov.di.authentication.frontendapi.services.UserMigrationService;
import uk.gov.di.authentication.shared.domain.CloudwatchMetrics;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.ClientSession;
import uk.gov.di.authentication.shared.entity.CountType;
import uk.gov.di.authentication.shared.entity.CredentialTrustLevel;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.TermsAndConditions;
import uk.gov.di.authentication.shared.entity.UserCredentials;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethod;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.helpers.SaltHelper;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthSessionService;
import uk.gov.di.authentication.shared.services.AuthenticationAttemptsService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.CommonPasswordsService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.SessionService;
import uk.gov.di.authentication.shared.services.mfa.MFAMethodsService;
import uk.gov.di.authentication.sharedtest.logging.CaptureLoggingExtension;

import java.net.URI;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import static java.lang.String.format;
import static java.util.Objects.nonNull;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.not;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.longThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_INVALID_CREDENTIALS;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.CLIENT_SESSION_ID;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.DI_PERSISTENT_SESSION_ID;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.ENCODED_DEVICE_DETAILS;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.IP_ADDRESS;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.SESSION_ID;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.VALID_HEADERS;
import static uk.gov.di.authentication.shared.domain.CloudwatchMetricDimensions.ENVIRONMENT;
import static uk.gov.di.authentication.shared.domain.CloudwatchMetricDimensions.FAILURE_REASON;
import static uk.gov.di.authentication.shared.entity.CountType.ENTER_AUTH_APP_CODE;
import static uk.gov.di.authentication.shared.entity.CountType.ENTER_EMAIL;
import static uk.gov.di.authentication.shared.entity.CountType.ENTER_PASSWORD;
import static uk.gov.di.authentication.shared.entity.CountType.ENTER_SMS_CODE;
import static uk.gov.di.authentication.shared.entity.JourneyType.REAUTHENTICATION;
import static uk.gov.di.authentication.shared.entity.mfa.MFAMethodType.SMS;
import static uk.gov.di.authentication.shared.services.AuditService.MetadataPair.pair;
import static uk.gov.di.authentication.sharedtest.helper.JsonArrayHelper.jsonArrayOf;
import static uk.gov.di.authentication.sharedtest.helper.RequestEventHelper.contextWithSourceIp;
import static uk.gov.di.authentication.sharedtest.logging.LogEventMatcher.withMessageContaining;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class LoginHandlerReauthenticationUsingAuthenticationAttemptsServiceTest {

    private static final String EMAIL = CommonTestVariables.EMAIL;
    private static final String INTERNAL_SECTOR_URI = "https://test.account.gov.uk";
    public static final int MAX_ALLOWED_RETRIES = 6;
    private final UserCredentials userCredentials =
            new UserCredentials().withEmail(EMAIL).withPassword(CommonTestVariables.PASSWORD);

    private final UserCredentials userCredentialsAuthApp =
            new UserCredentials()
                    .withEmail(EMAIL)
                    .withPassword(CommonTestVariables.PASSWORD)
                    .setMfaMethod(AUTH_APP_MFA_METHOD);
    private static final ClientID CLIENT_ID = new ClientID();
    private static final String CLIENT_NAME = "client-name";
    private static final String TEST_RP_PAIRWISE_ID = "test-rp-pairwise-id";
    private static final Subject INTERNAL_SUBJECT_ID = new Subject();
    private static final byte[] SALT = SaltHelper.generateNewSalt();
    private static final MFAMethod AUTH_APP_MFA_METHOD =
            new MFAMethod()
                    .withMfaMethodType(MFAMethodType.AUTH_APP.getValue())
                    .withMethodVerified(true)
                    .withEnabled(true);
    private static final Session session = new Session();
    private final Context context = mock(Context.class);
    private final Subject subject = mock(Subject.class);
    private final String expectedCommonSubject =
            ClientSubjectHelper.calculatePairwiseIdentifier(
                    INTERNAL_SUBJECT_ID.getValue(), "test.account.gov.uk", SALT);

    private final String validBodyWithReauthJourney =
            format(
                    "{ \"password\": \"%s\", \"email\": \"%s\", \"journeyType\": \"%s\"}",
                    CommonTestVariables.PASSWORD, EMAIL.toUpperCase(), REAUTHENTICATION);

    private final AuditContext auditContextWithAllUserInfo =
            new AuditContext(
                    CLIENT_ID.getValue(),
                    CLIENT_SESSION_ID,
                    SESSION_ID,
                    expectedCommonSubject,
                    EMAIL,
                    IP_ADDRESS,
                    CommonTestVariables.UK_MOBILE_NUMBER,
                    DI_PERSISTENT_SESSION_ID,
                    Optional.empty());

    private LoginHandler handler;

    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final AuthenticationService authenticationService = mock(AuthenticationService.class);
    private final SessionService sessionService = mock(SessionService.class);
    private final ClientSessionService clientSessionService = mock(ClientSessionService.class);
    private final ClientSession clientSession = mock(ClientSession.class);
    private final ClientService clientService = mock(ClientService.class);
    private final UserMigrationService userMigrationService = mock(UserMigrationService.class);
    private final AuditService auditService = mock(AuditService.class);
    private final CloudwatchMetricsService cloudwatchMetricsService =
            mock(CloudwatchMetricsService.class);
    private final CommonPasswordsService commonPasswordsService =
            mock(CommonPasswordsService.class);
    private final CodeStorageService codeStorageService = mock(CodeStorageService.class);
    private final AuthenticationAttemptsService authenticationAttemptsService =
            mock(AuthenticationAttemptsService.class);
    private final AuthSessionService authSessionService = mock(AuthSessionService.class);
    private final MFAMethodsService mfaMethodsService = mock(MFAMethodsService.class);

    @RegisterExtension
    private final CaptureLoggingExtension logging = new CaptureLoggingExtension(LoginHandler.class);

    @AfterEach
    void tearDown() {
        assertThat(logging.events(), not(hasItem(withMessageContaining(SESSION_ID))));
    }

    @BeforeEach
    void setUp() {
        when(configurationService.getEnvironment()).thenReturn("test");
        when(configurationService.getMaxPasswordRetries()).thenReturn(MAX_ALLOWED_RETRIES);
        when(configurationService.getTermsAndConditionsVersion()).thenReturn("1.0");
        when(configurationService.getInternalSectorUri()).thenReturn(INTERNAL_SECTOR_URI);
        when(configurationService.isAuthenticationAttemptsServiceEnabled()).thenReturn(true);
        when(configurationService.getMaxEmailReAuthRetries()).thenReturn(MAX_ALLOWED_RETRIES);
        when(configurationService.getCodeMaxRetries()).thenReturn(MAX_ALLOWED_RETRIES);

        when(clientSessionService.getClientSessionFromRequestHeaders(any()))
                .thenReturn(Optional.of(clientSession));

        when(context.getAwsRequestId()).thenReturn("aws-session-id");

        when(clientService.getClient(CLIENT_ID.getValue()))
                .thenReturn(Optional.of(generateClientRegistry()));

        when(authenticationService.getOrGenerateSalt(any(UserProfile.class))).thenReturn(SALT);

        handler =
                new LoginHandler(
                        configurationService,
                        sessionService,
                        authenticationService,
                        clientSessionService,
                        clientService,
                        codeStorageService,
                        userMigrationService,
                        auditService,
                        cloudwatchMetricsService,
                        commonPasswordsService,
                        authenticationAttemptsService,
                        authSessionService,
                        mfaMethodsService);
    }

    @ParameterizedTest
    @EnumSource(MFAMethodType.class)
    void
            shouldReturnErrorNotDeleteCountAndNotLockUserAccountOutAfterMaxNumberOfIncorrectPasswordsPresented(
                    MFAMethodType mfaMethodType) {
        try (MockedStatic<ClientSubjectHelper> clientSubjectHelperMockedStatic =
                Mockito.mockStatic(ClientSubjectHelper.class, Mockito.CALLS_REAL_METHODS)) {
            UserProfile userProfile = generateUserProfile(null);
            when(authenticationService.getUserProfileByEmailMaybe(EMAIL))
                    .thenReturn(Optional.of(userProfile));
            clientSubjectHelperMockedStatic
                    .when(() -> ClientSubjectHelper.getSubject(any(), any(), any(), any()))
                    .thenReturn(subject);
            when(subject.getValue()).thenReturn(TEST_RP_PAIRWISE_ID);

            when(authenticationAttemptsService.getCount(
                            any(), eq(REAUTHENTICATION), eq(ENTER_PASSWORD)))
                    .thenReturn(MAX_ALLOWED_RETRIES - 1);
            when(authenticationAttemptsService.getCountsByJourneyForSubjectIdAndRpPairwiseId(
                            any(String.class), any(String.class), eq(JourneyType.REAUTHENTICATION)))
                    .thenReturn(Map.of(ENTER_PASSWORD, MAX_ALLOWED_RETRIES - 1));

            when(configurationService.supportReauthSignoutEnabled()).thenReturn(true);

            usingValidSession();
            usingValidAuthSession();
            usingApplicableUserCredentialsWithLogin(mfaMethodType, false);

            var event = eventWithHeadersAndBody(VALID_HEADERS, validBodyWithReauthJourney);

            APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

            assertThat(result, hasStatus(400));
            assertThat(result, hasJsonBody(ErrorResponse.ERROR_1028));

            verify(authenticationAttemptsService, never()).deleteCount(any(), any(), any());

            verify(auditService, times(1))
                    .submitAuditEvent(
                            FrontendAuditableEvent.AUTH_REAUTH_FAILED,
                            auditContextWithAllUserInfo.withTxmaAuditEncoded(
                                    Optional.of(ENCODED_DEVICE_DETAILS)),
                            pair("rpPairwiseId", TEST_RP_PAIRWISE_ID),
                            pair("incorrect_email_attempt_count", 0),
                            pair("incorrect_password_attempt_count", 5),
                            pair("incorrect_otp_code_attempt_count", 0),
                            pair("failure-reason", "incorrect_password"));

            verify(cloudwatchMetricsService)
                    .incrementCounter(
                            CloudwatchMetrics.REAUTH_FAILED.getValue(),
                            Map.of(
                                    ENVIRONMENT.getValue(),
                                    configurationService.getEnvironment(),
                                    FAILURE_REASON.getValue(),
                                    "incorrect_password"));

            verify(auditService)
                    .submitAuditEvent(
                            AUTH_INVALID_CREDENTIALS,
                            auditContextWithAllUserInfo.withTxmaAuditEncoded(
                                    Optional.of(ENCODED_DEVICE_DETAILS)),
                            pair("internalSubjectId", userProfile.getSubjectID()),
                            pair(
                                    "incorrectPasswordCount",
                                    configurationService.getMaxPasswordRetries()),
                            pair(
                                    "attemptNoFailedAt",
                                    configurationService.getMaxPasswordRetries()));

            verify(cloudwatchMetricsService, never())
                    .incrementAuthenticationSuccess(
                            any(), any(), any(), any(), anyBoolean(), anyBoolean());
            verify(sessionService, never()).storeOrUpdateSession(any(Session.class), anyString());
        }
    }

    private static Stream<Arguments> reauthCountTypesAndMetadata() {
        return Stream.of(
                Arguments.arguments(
                        ENTER_EMAIL,
                        MAX_ALLOWED_RETRIES,
                        0,
                        0,
                        ReauthFailureReasons.INCORRECT_EMAIL.getValue()),
                Arguments.arguments(
                        ENTER_PASSWORD,
                        0,
                        MAX_ALLOWED_RETRIES,
                        0,
                        ReauthFailureReasons.INCORRECT_PASSWORD.getValue()),
                Arguments.arguments(
                        ENTER_SMS_CODE,
                        0,
                        0,
                        MAX_ALLOWED_RETRIES,
                        ReauthFailureReasons.INCORRECT_OTP.getValue()),
                Arguments.arguments(
                        ENTER_AUTH_APP_CODE,
                        0,
                        0,
                        MAX_ALLOWED_RETRIES,
                        ReauthFailureReasons.INCORRECT_OTP.getValue()));
    }

    @ParameterizedTest
    @MethodSource("reauthCountTypesAndMetadata")
    void shouldReturnErrorNotDeleteCountAndNotLockUserAccountOutIfUserHasAnyReauthLocks(
            CountType countType,
            int expectedEmailAttemptCount,
            int expectedPasswordAttemptCount,
            int expectedOtpAttemptCount,
            String expectedFailureReason) {
        try (MockedStatic<ClientSubjectHelper> clientSubjectHelperMockedStatic =
                Mockito.mockStatic(ClientSubjectHelper.class, Mockito.CALLS_REAL_METHODS)) {
            UserProfile userProfile = generateUserProfile(null);
            when(authenticationService.getUserProfileByEmailMaybe(EMAIL))
                    .thenReturn(Optional.of(userProfile));
            clientSubjectHelperMockedStatic
                    .when(() -> ClientSubjectHelper.getSubject(any(), any(), any(), any()))
                    .thenReturn(subject);
            when(subject.getValue()).thenReturn(TEST_RP_PAIRWISE_ID);
            when(authenticationAttemptsService.getCountsByJourneyForSubjectIdAndRpPairwiseId(
                            any(), any(), eq(JourneyType.REAUTHENTICATION)))
                    .thenReturn(Map.of(countType, MAX_ALLOWED_RETRIES));

            setupConfigurationServiceCountForCountType(countType, MAX_ALLOWED_RETRIES);

            when(configurationService.supportReauthSignoutEnabled()).thenReturn(true);

            usingValidSession();
            usingValidAuthSession();
            usingApplicableUserCredentialsWithLogin(SMS, true);

            var event = eventWithHeadersAndBody(VALID_HEADERS, validBodyWithReauthJourney);

            APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

            assertThat(result, hasStatus(400));
            assertThat(result, hasJsonBody(ErrorResponse.ERROR_1057));

            verify(authenticationAttemptsService, never()).deleteCount(any(), any(), any());

            verify(auditService, times(1))
                    .submitAuditEvent(
                            FrontendAuditableEvent.AUTH_REAUTH_FAILED,
                            auditContextWithAllUserInfo.withTxmaAuditEncoded(
                                    Optional.of(ENCODED_DEVICE_DETAILS)),
                            pair("rpPairwiseId", TEST_RP_PAIRWISE_ID),
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
        }
    }

    @ParameterizedTest
    @EnumSource(JourneyType.class)
    void
            shouldNotEmitReauthFailedAuditEventWhenJourneyTypeIsNotReauthenticationWhenUserAlreadyBlocked(
                    JourneyType journeyType) {
        UserProfile userProfile = generateUserProfile(null);
        when(authenticationService.getUserProfileByEmailMaybe(EMAIL))
                .thenReturn(Optional.of(userProfile));
        when(authenticationAttemptsService.getCount(
                        any(), eq(REAUTHENTICATION), eq(ENTER_PASSWORD)))
                .thenReturn(MAX_ALLOWED_RETRIES - 1);
        when(authenticationAttemptsService.getCountsByJourneyForSubjectIdAndRpPairwiseId(
                        any(), any(), eq(JourneyType.REAUTHENTICATION)))
                .thenReturn(Map.of(CountType.ENTER_PASSWORD, MAX_ALLOWED_RETRIES - 1))
                .thenReturn(Map.of(ENTER_PASSWORD, MAX_ALLOWED_RETRIES));

        setupConfigurationServiceCountForCountType(ENTER_PASSWORD, MAX_ALLOWED_RETRIES);

        when(configurationService.supportReauthSignoutEnabled()).thenReturn(true);

        usingValidSession();
        usingValidAuthSession();
        usingApplicableUserCredentialsWithLogin(SMS, false);

        String validBodyWithJourney =
                format(
                        "{ \"password\": \"%s\", \"email\": \"%s\", \"journeyType\": \"%s\"}",
                        CommonTestVariables.PASSWORD, EMAIL.toUpperCase(), journeyType);

        var event = eventWithHeadersAndBody(VALID_HEADERS, validBodyWithJourney);

        handler.handleRequest(event, context);

        if (journeyType != JourneyType.REAUTHENTICATION) {
            verify(auditService, never())
                    .submitAuditEvent(
                            eq(FrontendAuditableEvent.AUTH_REAUTH_FAILED),
                            any(AuditContext.class),
                            any(AuditService.MetadataPair[].class));
            verify(cloudwatchMetricsService, never())
                    .incrementCounter(
                            CloudwatchMetrics.REAUTH_FAILED.getValue(),
                            eq(
                                    Map.of(
                                            ENVIRONMENT.getValue(),
                                            configurationService.getEnvironment(),
                                            FAILURE_REASON.getValue(),
                                            anyString())));
        }
    }

    @ParameterizedTest
    @EnumSource(JourneyType.class)
    void
            shouldNotEmitReauthFailedAuditEventWhenJourneyTypeIsNotReauthWhenUserEntersTooManyIncorrectPasswords(
                    JourneyType journeyType) {
        UserProfile userProfile = generateUserProfile(null);
        when(authenticationService.getUserProfileByEmailMaybe(EMAIL))
                .thenReturn(Optional.of(userProfile));
        when(authenticationAttemptsService.getCountsByJourneyForSubjectIdAndRpPairwiseId(
                        any(), any(), eq(JourneyType.REAUTHENTICATION)))
                .thenReturn(Map.of(ENTER_PASSWORD, MAX_ALLOWED_RETRIES));

        setupConfigurationServiceCountForCountType(ENTER_PASSWORD, MAX_ALLOWED_RETRIES);

        when(configurationService.supportReauthSignoutEnabled()).thenReturn(true);

        usingValidSession();
        usingValidAuthSession();
        usingApplicableUserCredentialsWithLogin(SMS, false);

        String validBodyWithJourney =
                format(
                        "{ \"password\": \"%s\", \"email\": \"%s\", \"journeyType\": \"%s\"}",
                        CommonTestVariables.PASSWORD, EMAIL.toUpperCase(), journeyType);

        var event = eventWithHeadersAndBody(VALID_HEADERS, validBodyWithJourney);

        handler.handleRequest(event, context);

        if (journeyType != JourneyType.REAUTHENTICATION) {
            verify(auditService, never())
                    .submitAuditEvent(
                            eq(FrontendAuditableEvent.AUTH_REAUTH_FAILED),
                            any(AuditContext.class),
                            any(AuditService.MetadataPair[].class));
            verify(cloudwatchMetricsService, never())
                    .incrementCounter(
                            CloudwatchMetrics.REAUTH_FAILED.getValue(),
                            eq(
                                    Map.of(
                                            ENVIRONMENT.getValue(),
                                            configurationService.getEnvironment(),
                                            FAILURE_REASON.getValue(),
                                            anyString())));
        }
    }

    @Test
    void shouldIncrementRelevantCountWhenCredentialsAreInvalid() {
        UserProfile userProfile = generateUserProfile(null);
        when(authenticationService.getUserProfileByEmailMaybe(EMAIL))
                .thenReturn(Optional.of(userProfile));
        usingApplicableUserCredentialsWithLogin(SMS, false);

        when(configurationService.supportReauthSignoutEnabled()).thenReturn(true);

        when(configurationService.getReauthEnterPasswordCountTTL()).thenReturn(120l);

        when(authenticationAttemptsService.getCount(any(), any(), any())).thenReturn(1);

        usingValidSession();
        usingValidAuthSession();

        var event = eventWithHeadersAndBody(VALID_HEADERS, validBodyWithReauthJourney);

        handler.handleRequest(event, context);

        verify(authenticationAttemptsService)
                .createOrIncrementCount(
                        eq(userProfile.getSubjectID()),
                        longThat(
                                ttl -> {
                                    long expectedMin =
                                            NowHelper.nowPlus(120, ChronoUnit.SECONDS)
                                                            .toInstant()
                                                            .getEpochSecond()
                                                    - 1;
                                    long expectedMax =
                                            NowHelper.nowPlus(120, ChronoUnit.SECONDS)
                                                            .toInstant()
                                                            .getEpochSecond()
                                                    + 1;
                                    return ttl >= expectedMin && ttl <= expectedMax;
                                }),
                        eq(REAUTHENTICATION),
                        eq(ENTER_PASSWORD));
    }

    @Test
    void shouldIncrementRelevantCountWhenLimitHasExceeded() {
        UserProfile userProfile = generateUserProfile(null);
        when(authenticationService.getUserProfileByEmailMaybe(EMAIL))
                .thenReturn(Optional.of(userProfile));
        usingApplicableUserCredentialsWithLogin(SMS, false);

        when(configurationService.supportReauthSignoutEnabled()).thenReturn(true);
        when(configurationService.getReauthEnterPasswordCountTTL()).thenReturn(120l);

        when(authenticationAttemptsService.getCount(any(), any(), any()))
                .thenReturn(MAX_ALLOWED_RETRIES - 1);

        usingValidSession();
        usingValidAuthSession();

        var event = eventWithHeadersAndBody(VALID_HEADERS, validBodyWithReauthJourney);

        handler.handleRequest(event, context);

        verify(authenticationAttemptsService)
                .createOrIncrementCount(
                        eq(userProfile.getSubjectID()),
                        longThat(
                                ttl -> {
                                    long expectedMin =
                                            NowHelper.nowPlus(120, ChronoUnit.SECONDS)
                                                            .toInstant()
                                                            .getEpochSecond()
                                                    - 1;
                                    long expectedMax =
                                            NowHelper.nowPlus(120, ChronoUnit.SECONDS)
                                                            .toInstant()
                                                            .getEpochSecond()
                                                    + 1;
                                    return ttl >= expectedMin && ttl <= expectedMax;
                                }),
                        eq(REAUTHENTICATION),
                        eq(ENTER_PASSWORD));
    }

    private AuthenticationRequest generateAuthRequest() {
        return generateAuthRequest(null);
    }

    private AuthenticationRequest generateAuthRequest(CredentialTrustLevel credentialTrustLevel) {
        Scope scope = new Scope();
        scope.add(OIDCScopeValue.OPENID);
        AuthenticationRequest.Builder builder =
                new AuthenticationRequest.Builder(
                                ResponseType.CODE,
                                scope,
                                CLIENT_ID,
                                URI.create("http://localhost/redirect"))
                        .state(new State())
                        .nonce(new Nonce());
        if (nonNull(credentialTrustLevel)) {
            builder.customParameter("vtr", jsonArrayOf(credentialTrustLevel.getValue()));
        }
        return builder.build();
    }

    private void usingValidSession() {
        when(sessionService.getSessionFromRequestHeaders(anyMap()))
                .thenReturn(Optional.of(session));
    }

    private void usingValidAuthSession() {
        when(authSessionService.getSessionFromRequestHeaders(anyMap()))
                .thenReturn(
                        Optional.of(
                                new AuthSessionItem()
                                        .withSessionId(SESSION_ID)
                                        .withEmailAddress(EMAIL)
                                        .withAccountState(AuthSessionItem.AccountState.UNKNOWN)
                                        .withClientId(CLIENT_ID.getValue())));
    }

    private UserCredentials usingApplicableUserCredentials(MFAMethodType mfaMethodType) {
        UserCredentials applicableUserCredentials =
                mfaMethodType.equals(SMS) ? userCredentials : userCredentialsAuthApp;
        when(authenticationService.getUserCredentialsFromEmail(EMAIL))
                .thenReturn(applicableUserCredentials);
        return applicableUserCredentials;
    }

    private UserCredentials usingApplicableUserCredentialsWithLogin(
            MFAMethodType mfaMethodType, boolean loginSuccessful) {
        UserCredentials applicableUserCredentials = usingApplicableUserCredentials(mfaMethodType);
        when(authenticationService.login(applicableUserCredentials, CommonTestVariables.PASSWORD))
                .thenReturn(loginSuccessful);
        return applicableUserCredentials;
    }

    private UserProfile generateUserProfile(String legacySubjectId) {
        return new UserProfile()
                .withEmail(EMAIL)
                .withEmailVerified(true)
                .withPhoneNumber(CommonTestVariables.UK_MOBILE_NUMBER)
                .withPhoneNumberVerified(true)
                .withPublicSubjectID(new Subject().getValue())
                .withSubjectID(INTERNAL_SUBJECT_ID.getValue())
                .withLegacySubjectID(legacySubjectId)
                .withTermsAndConditions(
                        new TermsAndConditions("1.0", NowHelper.now().toInstant().toString()));
    }

    private ClientRegistry generateClientRegistry() {
        return new ClientRegistry()
                .withClientID(CLIENT_ID.getValue())
                .withClientName(CLIENT_NAME)
                .withSectorIdentifierUri("https://test.com")
                .withSubjectType("public");
    }

    private APIGatewayProxyRequestEvent eventWithHeadersAndBody(
            Map<String, String> headers, String body) {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setRequestContext(contextWithSourceIp(IP_ADDRESS));
        event.setHeaders(headers);
        event.setBody(body);
        return event;
    }

    private void setupConfigurationServiceCountForCountType(
            CountType countType, int retriesAllowed) {
        switch (countType) {
            case ENTER_EMAIL -> when(configurationService.getMaxEmailReAuthRetries())
                    .thenReturn(retriesAllowed);
            case ENTER_PASSWORD -> when(configurationService.getMaxPasswordRetries())
                    .thenReturn(retriesAllowed);
            case ENTER_AUTH_APP_CODE, ENTER_SMS_CODE, ENTER_EMAIL_CODE -> when(configurationService
                            .getCodeMaxRetries())
                    .thenReturn(retriesAllowed);
        }
    }
}
