package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent;
import uk.gov.di.authentication.frontendapi.entity.LoginResponse;
import uk.gov.di.authentication.frontendapi.entity.PasswordResetType;
import uk.gov.di.authentication.frontendapi.entity.mfa.AuthAppMfaMethodResponse;
import uk.gov.di.authentication.frontendapi.entity.mfa.MfaMethodResponse;
import uk.gov.di.authentication.frontendapi.entity.mfa.SmsMfaMethodResponse;
import uk.gov.di.authentication.frontendapi.serialization.MfaMethodResponseAdapter;
import uk.gov.di.authentication.frontendapi.services.UserMigrationService;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.entity.CodeRequestType;
import uk.gov.di.authentication.shared.entity.CredentialTrustLevel;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.PriorityIdentifier;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.entity.TermsAndConditions;
import uk.gov.di.authentication.shared.entity.UserCredentials;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethod;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.helpers.NoDefaultMfaMethodLogHelper;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.helpers.SaltHelper;
import uk.gov.di.authentication.shared.helpers.TestUserHelper;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthSessionService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;
import uk.gov.di.authentication.shared.services.CommonPasswordsService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.SerializationService;
import uk.gov.di.authentication.shared.services.mfa.MFAMethodsService;
import uk.gov.di.authentication.sharedtest.helper.CommonTestVariables;
import uk.gov.di.authentication.sharedtest.logging.CaptureLoggingExtension;
import uk.gov.di.authentication.userpermissions.PermissionDecisionManager;
import uk.gov.di.authentication.userpermissions.UserActionsManager;
import uk.gov.di.authentication.userpermissions.entity.Decision;
import uk.gov.di.authentication.userpermissions.entity.DecisionError;
import uk.gov.di.authentication.userpermissions.entity.ForbiddenReason;
import uk.gov.di.authentication.userpermissions.entity.PermissionContext;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.frontendapi.helpers.ApiGatewayProxyRequestHelper.apiRequestEventWithHeadersAndBody;
import static uk.gov.di.authentication.frontendapi.helpers.FrontendApiPhoneNumberHelper.redactPhoneNumber;
import static uk.gov.di.authentication.shared.entity.CredentialTrustLevel.LOW_LEVEL;
import static uk.gov.di.authentication.shared.entity.CredentialTrustLevel.MEDIUM_LEVEL;
import static uk.gov.di.authentication.shared.entity.PriorityIdentifier.DEFAULT;
import static uk.gov.di.authentication.shared.entity.mfa.MFAMethodType.AUTH_APP;
import static uk.gov.di.authentication.shared.entity.mfa.MFAMethodType.SMS;
import static uk.gov.di.authentication.shared.services.AuditService.MetadataPair.pair;
import static uk.gov.di.authentication.shared.services.CodeStorageService.CODE_BLOCKED_KEY_PREFIX;
import static uk.gov.di.authentication.shared.services.CodeStorageService.CODE_REQUEST_BLOCKED_KEY_PREFIX;
import static uk.gov.di.authentication.shared.services.mfa.MfaRetrieveFailureReason.UNEXPECTED_ERROR_CREATING_MFA_IDENTIFIER_FOR_NON_MIGRATED_AUTH_APP;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.CLIENT_SESSION_ID;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.DI_PERSISTENT_SESSION_ID;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.ENCODED_DEVICE_DETAILS;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.IP_ADDRESS;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.SESSION_ID;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.VALID_HEADERS;
import static uk.gov.di.authentication.sharedtest.logging.LogEventMatcher.withMessageContaining;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class LoginHandlerTest {

    private static final String EMAIL = CommonTestVariables.EMAIL;
    private static final String INTERNAL_SECTOR_URI = "https://test.account.gov.uk";
    private static final String SECTOR_IDENTIFIER_HOST = "test.com";
    public static final int MAX_ALLOWED_PASSWORD_RETRIES = 6;
    private final UserCredentials userCredentials =
            new UserCredentials().withEmail(EMAIL).withPassword(CommonTestVariables.PASSWORD);

    private final UserCredentials userCredentialsAuthApp =
            new UserCredentials()
                    .withEmail(EMAIL)
                    .withPassword(CommonTestVariables.PASSWORD)
                    .setMfaMethod(AUTH_APP_MFA_METHOD);
    private static final ClientID CLIENT_ID = new ClientID();
    private static final String CLIENT_NAME = "client-name";
    private static final Subject INTERNAL_SUBJECT_ID = new Subject();
    private static final byte[] SALT = SaltHelper.generateNewSalt();
    private static final MFAMethod AUTH_APP_MFA_METHOD =
            new MFAMethod()
                    .withMfaMethodType(MFAMethodType.AUTH_APP.getValue())
                    .withMethodVerified(true)
                    .withEnabled(true);
    private static final MFAMethod DEFAULT_SMS_MFA_METHOD =
            MFAMethod.smsMfaMethod(
                    true,
                    true,
                    CommonTestVariables.UK_MOBILE_NUMBER,
                    PriorityIdentifier.DEFAULT,
                    "some-mfa-id");
    private static final MFAMethod DEFAULT_AUTH_APP_MFA_METHOD =
            MFAMethod.authAppMfaMethod(
                    "some-credential", true, true, PriorityIdentifier.DEFAULT, "another-mfa-id");
    private static final Json objectMapper =
            new SerializationService(
                    Map.of(MfaMethodResponse.class, new MfaMethodResponseAdapter()));
    private LoginHandler handler;
    private final Context context = mock(Context.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final AuthenticationService authenticationService = mock(AuthenticationService.class);
    private final UserMigrationService userMigrationService = mock(UserMigrationService.class);
    private final AuditService auditService = mock(AuditService.class);
    private final CloudwatchMetricsService cloudwatchMetricsService =
            mock(CloudwatchMetricsService.class);
    private final CommonPasswordsService commonPasswordsService =
            mock(CommonPasswordsService.class);
    private final AuthSessionService authSessionService = mock(AuthSessionService.class);
    private final MFAMethodsService mfaMethodsService = mock(MFAMethodsService.class);
    private final PermissionDecisionManager permissionDecisionManager =
            mock(PermissionDecisionManager.class);
    private final UserActionsManager userActionsManager = mock(UserActionsManager.class);
    private final TestUserHelper testUserHelper = mock(TestUserHelper.class);
    private final String expectedCommonSubject =
            ClientSubjectHelper.calculatePairwiseIdentifier(
                    INTERNAL_SUBJECT_ID.getValue(), "test.account.gov.uk", SALT);

    private final String validBodyWithEmailAndPassword =
            format(
                    "{ \"password\": \"%s\", \"email\": \"%s\" }",
                    CommonTestVariables.PASSWORD, EMAIL.toUpperCase());

    private final String validBodyWithReauthJourney =
            format(
                    "{ \"password\": \"%s\", \"email\": \"%s\", \"journeyType\": \"%s\"}",
                    CommonTestVariables.PASSWORD,
                    EMAIL.toUpperCase(),
                    JourneyType.REAUTHENTICATION);

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
                    AuditService.UNKNOWN);

    private final AuditContext auditContextWithoutUserInfo =
            auditContextWithAllUserInfo
                    .withSubjectId(AuditService.UNKNOWN)
                    .withPhoneNumber(AuditService.UNKNOWN);

    private final Decision aTemporarilyLockedOutDecision =
            new Decision.TemporarilyLockedOut(
                    ForbiddenReason.EXCEEDED_INCORRECT_PASSWORD_SUBMISSION_LIMIT,
                    MAX_ALLOWED_PASSWORD_RETRIES,
                    Instant.now().plus(15, java.time.temporal.ChronoUnit.MINUTES),
                    false);

    @RegisterExtension
    private final CaptureLoggingExtension logging = new CaptureLoggingExtension(LoginHandler.class);

    @RegisterExtension
    private final CaptureLoggingExtension noDefaultMfaMethodLogging =
            new CaptureLoggingExtension(NoDefaultMfaMethodLogHelper.class);

    @AfterEach
    void tearDown() {
        assertThat(logging.events(), not(hasItem(withMessageContaining(SESSION_ID))));
    }

    @BeforeEach
    void setUp() {
        when(configurationService.getMaxPasswordRetries()).thenReturn(MAX_ALLOWED_PASSWORD_RETRIES);
        when(configurationService.getTermsAndConditionsVersion()).thenReturn("1.0");
        when(configurationService.getEnvironment()).thenReturn("test");
        when(context.getAwsRequestId()).thenReturn("aws-session-id");
        when(configurationService.getInternalSectorUri()).thenReturn(INTERNAL_SECTOR_URI);
        when(authenticationService.getOrGenerateSalt(any(UserProfile.class))).thenReturn(SALT);
        when(permissionDecisionManager.canReceivePassword(any(), any()))
                .thenReturn(Result.success(new Decision.Permitted(0)));
        when(permissionDecisionManager.canSendSmsOtpNotification(any(), any()))
                .thenReturn(Result.success(new Decision.Permitted(0)));
        when(permissionDecisionManager.canVerifyMfaOtp(any(), any()))
                .thenReturn(Result.success(new Decision.Permitted(0)));
        handler =
                new LoginHandler(
                        configurationService,
                        authenticationService,
                        userMigrationService,
                        auditService,
                        cloudwatchMetricsService,
                        commonPasswordsService,
                        authSessionService,
                        mfaMethodsService,
                        permissionDecisionManager,
                        userActionsManager,
                        testUserHelper);
    }

    @Test
    void shouldReturn200IfLoginIsSuccessfulAndMfaNotRequired() {
        setupExistingUserInDatabase(EMAIL);
        usingApplicableUserCredentialsWithLogin(SMS, true);
        usingValidAuthSessionWithRequestedCredentialStrength(LOW_LEVEL);

        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, validBodyWithEmailAndPassword);

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(200));

        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.AUTH_LOG_IN_SUCCESS,
                        auditContextWithAllUserInfo.withTxmaAuditEncoded(ENCODED_DEVICE_DETAILS),
                        pair("internalSubjectId", INTERNAL_SUBJECT_ID.getValue()));

        verify(cloudwatchMetricsService)
                .incrementAuthenticationSuccessWithoutMfa(
                        AuthSessionItem.AccountState.EXISTING,
                        CLIENT_ID.getValue(),
                        CLIENT_NAME,
                        "P0",
                        false);

        verifyInternalCommonSubjectIdentifierSaved();
    }

    @Test
    void shouldSetAchievedCredentialTrustLowWhenMfaNotRequiredAndNoPreviousValue() {
        setupExistingUserInDatabase(EMAIL);
        usingApplicableUserCredentialsWithLogin(SMS, true);
        usingValidAuthSessionWithRequestedCredentialStrength(LOW_LEVEL);

        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, validBodyWithEmailAndPassword);

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(200));

        verify(authSessionService)
                .updateSession(
                        argThat(
                                as ->
                                        as.getAchievedCredentialStrength() == LOW_LEVEL
                                                && as.getIsNewAccount()
                                                        == AuthSessionItem.AccountState.EXISTING));
    }

    @Test
    void shouldRetainPreviouslyMediumCredentialTrustWhenOnLowLevelJourney() {
        setupExistingUserInDatabase(EMAIL);
        usingApplicableUserCredentialsWithLogin(SMS, true);
        usingValidAuthSessionWithAchievedAndRequestedCredentialStrength(MEDIUM_LEVEL, LOW_LEVEL);

        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, validBodyWithEmailAndPassword);

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(200));

        verify(authSessionService)
                .updateSession(
                        argThat(
                                as ->
                                        as.getAchievedCredentialStrength() == MEDIUM_LEVEL
                                                && as.getIsNewAccount()
                                                        == AuthSessionItem.AccountState.EXISTING));
    }

    @Test
    void shouldRetainLowCredentialTrustLevelWhenPreviouslyObtained() {
        setupExistingUserInDatabase(EMAIL);
        usingApplicableUserCredentialsWithLogin(SMS, true);
        usingValidAuthSessionWithAchievedAndRequestedCredentialStrength(LOW_LEVEL, LOW_LEVEL);

        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, validBodyWithEmailAndPassword);

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(200));

        verify(authSessionService)
                .updateSession(
                        argThat(
                                as ->
                                        as.getAchievedCredentialStrength() == LOW_LEVEL
                                                && as.getIsNewAccount()
                                                        == AuthSessionItem.AccountState.EXISTING));
    }

    @ParameterizedTest
    @EnumSource(MFAMethodType.class)
    void shouldReturn200IfLoginIsSuccessfulAndMfaIsRequired(MFAMethodType mfaMethodType) {
        setupExistingUserInDatabase(EMAIL);
        usingValidAuthSessionWithRequestedCredentialStrength(MEDIUM_LEVEL);
        usingApplicableUserCredentialsWithLogin(mfaMethodType, true);

        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, validBodyWithEmailAndPassword);
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(200));

        verifyNoInteractions(cloudwatchMetricsService);

        verifyInternalCommonSubjectIdentifierSaved();
    }

    @Test
    void shouldReturn200IfLoginIsSuccessfulAndTermsAndConditionsNotAccepted()
            throws Json.JsonException {
        when(configurationService.getTermsAndConditionsVersion()).thenReturn("2.0");
        var userProfile =
                generateUserProfile(null)
                        .withTermsAndConditions(
                                new TermsAndConditions(
                                        "1.0", NowHelper.now().toInstant().toString()));
        setupUserInDatabase(EMAIL, userProfile);
        usingValidAuthSession();
        usingApplicableUserCredentialsWithLogin(SMS, true);

        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, validBodyWithEmailAndPassword);
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(200));

        LoginResponse response = objectMapper.readValue(result.getBody(), LoginResponse.class);

        assertThat(response.latestTermsAndConditionsAccepted(), equalTo(false));
    }

    @Test
    void termsAndConditionsShouldBeAcceptedIfClientIsSmokeTestClient() throws Json.JsonException {
        when(configurationService.getTermsAndConditionsVersion()).thenReturn("2.0");
        var userProfile =
                generateUserProfile(null)
                        .withTermsAndConditions(
                                new TermsAndConditions(
                                        "1.0", NowHelper.now().toInstant().toString()));
        setupUserInDatabase(EMAIL, userProfile);
        usingApplicableUserCredentialsWithLogin(SMS, true);
        usingValidAuthSessionInSmokeTest();

        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, validBodyWithEmailAndPassword);
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(200));

        LoginResponse response = objectMapper.readValue(result.getBody(), LoginResponse.class);

        assertThat(response.latestTermsAndConditionsAccepted(), equalTo(true));
    }

    @Test
    void shouldReturn200WithCorrectMfaMethodVerifiedStatus() throws Json.JsonException {
        MFAMethod mfaMethod =
                MFAMethod.authAppMfaMethod(
                        "some-credential",
                        false,
                        true,
                        PriorityIdentifier.DEFAULT,
                        "another-mfa-id");
        setupExistingUserInDatabase(EMAIL);
        var userCredentials =
                new UserCredentials()
                        .withEmail(EMAIL)
                        .withPassword(CommonTestVariables.PASSWORD)
                        .setMfaMethod(mfaMethod);
        when(authenticationService.login(userCredentials, CommonTestVariables.PASSWORD))
                .thenReturn(true);
        when(authenticationService.getUserCredentialsFromEmail(EMAIL)).thenReturn(userCredentials);
        when(mfaMethodsService.getMfaMethods(EMAIL)).thenReturn(Result.success(List.of(mfaMethod)));
        usingValidAuthSessionWithRequestedCredentialStrength(MEDIUM_LEVEL);

        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, validBodyWithEmailAndPassword);
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(200));

        var response = objectMapper.readValue(result.getBody(), LoginResponse.class);
        assertThat(response.mfaMethodType(), equalTo(SMS));
        assertThat(response.mfaMethodVerified(), equalTo(true));
    }

    private static Stream<Arguments> migratedMfaMethodsToExpectedLoginResponse() {
        var expectedRedactedPhoneNumber = redactPhoneNumber(CommonTestVariables.UK_MOBILE_NUMBER);
        return Stream.of(
                Arguments.of(
                        DEFAULT_SMS_MFA_METHOD,
                        new LoginResponse(
                                expectedRedactedPhoneNumber,
                                true,
                                SMS,
                                true,
                                List.of(
                                        new SmsMfaMethodResponse(
                                                "some-mfa-id",
                                                SMS,
                                                PriorityIdentifier.DEFAULT,
                                                expectedRedactedPhoneNumber)),
                                false)),
                Arguments.of(
                        DEFAULT_AUTH_APP_MFA_METHOD,
                        new LoginResponse(
                                null,
                                true,
                                AUTH_APP,
                                true,
                                List.of(
                                        new AuthAppMfaMethodResponse(
                                                "another-mfa-id",
                                                AUTH_APP,
                                                PriorityIdentifier.DEFAULT)),
                                false)));
    }

    @ParameterizedTest
    @MethodSource("migratedMfaMethodsToExpectedLoginResponse")
    void shouldReturn200WithCorrectMfaMethodsForMigratedUser(
            MFAMethod mfaMethod, LoginResponse expectedResponse) throws Json.JsonException {
        var userProfile =
                generateUserProfile(null)
                        .withMfaMethodsMigrated(true)
                        .withPhoneNumber(null)
                        .withPhoneNumberVerified(false);
        setupUserInDatabase(EMAIL, userProfile);
        var migratedUserCredentials =
                new UserCredentials()
                        .withEmail(EMAIL)
                        .withPassword(CommonTestVariables.PASSWORD)
                        .setMfaMethod(mfaMethod);

        when(authenticationService.login(migratedUserCredentials, CommonTestVariables.PASSWORD))
                .thenReturn(true);
        when(authenticationService.getUserCredentialsFromEmail(EMAIL))
                .thenReturn(migratedUserCredentials);
        when(mfaMethodsService.getMfaMethods(EMAIL)).thenReturn(Result.success(List.of(mfaMethod)));
        usingValidAuthSessionWithRequestedCredentialStrength(MEDIUM_LEVEL);

        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, validBodyWithEmailAndPassword);
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(200));

        var response = objectMapper.readValue(result.getBody(), LoginResponse.class);
        assertEquals(expectedResponse, response);
    }

    private static Stream<Arguments> mfaMethodsExpectedFromMfaMethodsService() {
        var expectedRedactedPhoneNumber = redactPhoneNumber(CommonTestVariables.UK_MOBILE_NUMBER);
        return Stream.of(
                Arguments.of(
                        true,
                        List.of(DEFAULT_SMS_MFA_METHOD),
                        new LoginResponse(
                                expectedRedactedPhoneNumber,
                                true,
                                SMS,
                                true,
                                List.of(
                                        new SmsMfaMethodResponse(
                                                "some-mfa-id",
                                                SMS,
                                                PriorityIdentifier.DEFAULT,
                                                expectedRedactedPhoneNumber)),
                                false)),
                Arguments.of(
                        true,
                        List.of(DEFAULT_AUTH_APP_MFA_METHOD),
                        new LoginResponse(
                                null,
                                true,
                                AUTH_APP,
                                true,
                                List.of(
                                        new AuthAppMfaMethodResponse(
                                                "another-mfa-id",
                                                AUTH_APP,
                                                PriorityIdentifier.DEFAULT)),
                                false)),
                Arguments.of(
                        false,
                        List.of(DEFAULT_SMS_MFA_METHOD),
                        new LoginResponse(
                                expectedRedactedPhoneNumber,
                                true,
                                SMS,
                                true,
                                List.of(
                                        new SmsMfaMethodResponse(
                                                "some-mfa-id",
                                                SMS,
                                                PriorityIdentifier.DEFAULT,
                                                expectedRedactedPhoneNumber)),
                                false)),
                Arguments.of(
                        false,
                        List.of(DEFAULT_AUTH_APP_MFA_METHOD),
                        new LoginResponse(
                                null,
                                true,
                                AUTH_APP,
                                true,
                                List.of(
                                        new AuthAppMfaMethodResponse(
                                                "another-mfa-id",
                                                AUTH_APP,
                                                PriorityIdentifier.DEFAULT)),
                                false)));
    }

    @ParameterizedTest
    @MethodSource("mfaMethodsExpectedFromMfaMethodsService")
    void shouldReturnCorrectMfaMethodsFromMfaMethodsService(
            boolean migrated, List<MFAMethod> mfaMethods, LoginResponse expectedResponse)
            throws Json.JsonException {
        var defaultMfa =
                mfaMethods.stream()
                        .filter(mfaMethod -> DEFAULT.name().equals(mfaMethod.getPriority()))
                        .findFirst();
        boolean hasPhoneNumberDefaultMfaMethod =
                defaultMfa.isPresent()
                        && MFAMethodType.valueOf(defaultMfa.get().getMfaMethodType()) == SMS;
        var testUserProfile =
                generateUserProfile(null)
                        .withMfaMethodsMigrated(migrated)
                        .withPhoneNumber(
                                hasPhoneNumberDefaultMfaMethod && !migrated
                                        ? defaultMfa.get().getDestination()
                                        : null)
                        .withPhoneNumberVerified(hasPhoneNumberDefaultMfaMethod && !migrated);
        setupUserInDatabase(EMAIL, testUserProfile);
        var testUserCredentials =
                new UserCredentials()
                        .withEmail(EMAIL)
                        .withPassword(CommonTestVariables.PASSWORD)
                        .setMfaMethod(mfaMethods.get(0));

        when(authenticationService.login(testUserCredentials, CommonTestVariables.PASSWORD))
                .thenReturn(true);
        when(authenticationService.getUserCredentialsFromEmail(EMAIL))
                .thenReturn(testUserCredentials);
        when(mfaMethodsService.getMfaMethods(EMAIL)).thenReturn(Result.success(mfaMethods));
        usingValidAuthSessionWithRequestedCredentialStrength(MEDIUM_LEVEL);

        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, validBodyWithEmailAndPassword);
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(200));

        var response = objectMapper.readValue(result.getBody(), LoginResponse.class);
        assertEquals(expectedResponse, response);
    }

    @Test
    void shouldReturn200IfLoginIsSuccessfulButPasswordWasCommonPassword()
            throws Json.JsonException {
        when(commonPasswordsService.isCommonPassword(anyString())).thenReturn(true);
        setupExistingUserInDatabase(EMAIL);
        usingValidAuthSession();
        usingApplicableUserCredentialsWithLogin(SMS, true);

        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, validBodyWithEmailAndPassword);
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);
        assertThat(result, hasStatus(200));

        LoginResponse response = objectMapper.readValue(result.getBody(), LoginResponse.class);
        assertThat(response.passwordChangeRequired(), equalTo(true));
        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.AUTH_LOG_IN_SUCCESS,
                        auditContextWithAllUserInfo.withTxmaAuditEncoded(ENCODED_DEVICE_DETAILS),
                        pair("internalSubjectId", INTERNAL_SUBJECT_ID.getValue()),
                        pair("passwordResetType", PasswordResetType.FORCED_WEAK_PASSWORD));
    }

    @Test
    void shouldReturn200IfMigratedUserHasBeenProcessesSuccessfully() {
        String legacySubjectId = new Subject().getValue();
        UserProfile userProfile = generateUserProfile(legacySubjectId);
        setupUserInDatabase(EMAIL, userProfile);
        UserCredentials applicableUserCredentials =
                usingApplicableUserCredentialsWithLogin(AUTH_APP, false);
        applicableUserCredentials.withPassword(null);
        when(userMigrationService.processMigratedUser(
                        applicableUserCredentials, CommonTestVariables.PASSWORD))
                .thenReturn(true);
        usingValidAuthSession();

        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, validBodyWithEmailAndPassword);
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(200));
    }

    @Test
    void
            shouldReturnErrorNotLockUserAccountAndRetainCountsOutAfterMaxNumberOfIncorrectPasswordsPresentedDuringReauthJourney() {
        var userProfile = setupExistingUserInDatabase(EMAIL);
        var maxRetriesAllowed = configurationService.getMaxPasswordRetries();
        when(permissionDecisionManager.canReceivePassword(any(), any()))
                .thenReturn(Result.success(new Decision.Permitted(maxRetriesAllowed - 1)))
                .thenReturn(Result.success(aTemporarilyLockedOutDecision));

        usingValidAuthSession();
        usingApplicableUserCredentialsWithLogin(AUTH_APP, false);

        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, validBodyWithReauthJourney);

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.TOO_MANY_INVALID_PW_ENTERED));

        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.AUTH_INVALID_CREDENTIALS,
                        auditContextWithAllUserInfo.withTxmaAuditEncoded(ENCODED_DEVICE_DETAILS),
                        pair("internalSubjectId", userProfile.getSubjectID()),
                        pair(
                                "incorrectPasswordCount",
                                configurationService.getMaxPasswordRetries()),
                        pair("attemptNoFailedAt", configurationService.getMaxPasswordRetries()));

        verify(authSessionService, never()).updateSession(any(AuthSessionItem.class));
    }

    @Test
    void shouldKeepUserLockedWhenTheyEnterSuccessfulLoginRequestInNewSession() {
        setupExistingUserInDatabase(EMAIL);
        when(permissionDecisionManager.canReceivePassword(any(), any()))
                .thenReturn(Result.success(aTemporarilyLockedOutDecision));
        usingValidAuthSession();
        usingApplicableUserCredentialsWithLogin(SMS, true);

        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, validBodyWithEmailAndPassword);

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.TOO_MANY_INVALID_PW_ENTERED));

        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.AUTH_ACCOUNT_TEMPORARILY_LOCKED,
                        auditContextWithAllUserInfo.withTxmaAuditEncoded(ENCODED_DEVICE_DETAILS),
                        pair("internalSubjectId", INTERNAL_SUBJECT_ID.getValue()),
                        pair("attemptNoFailedAt", configurationService.getMaxPasswordRetries()),
                        pair(
                                "number_of_attempts_user_allowed_to_login",
                                configurationService.getMaxPasswordRetries()));
        verify(authSessionService, never()).updateSession(any(AuthSessionItem.class));
    }

    @Test
    void shouldReturn500WhenPermissionDecisionManagerFails() {
        setupExistingUserInDatabase(EMAIL);
        when(permissionDecisionManager.canReceivePassword(any(), any()))
                .thenReturn(Result.failure(DecisionError.STORAGE_SERVICE_ERROR));
        usingValidAuthSession();
        usingApplicableUserCredentialsWithLogin(SMS, true);

        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, validBodyWithEmailAndPassword);

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(500));
        verify(authSessionService, never()).updateSession(any(AuthSessionItem.class));
    }

    @Test
    void shouldReturn401IfUserHasInvalidCredentials() {
        setupExistingUserInDatabase(EMAIL);
        usingApplicableUserCredentialsWithLogin(SMS, false);
        when(permissionDecisionManager.canReceivePassword(any(), any()))
                .thenReturn(Result.success(new Decision.Permitted(0)))
                .thenReturn(Result.success(new Decision.Permitted(1)));

        usingValidAuthSession();

        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, validBodyWithEmailAndPassword);
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.AUTH_INVALID_CREDENTIALS,
                        auditContextWithAllUserInfo.withTxmaAuditEncoded(ENCODED_DEVICE_DETAILS),
                        pair("internalSubjectId", INTERNAL_SUBJECT_ID.getValue()),
                        pair("incorrectPasswordCount", 1),
                        pair("attemptNoFailedAt", MAX_ALLOWED_PASSWORD_RETRIES));

        assertThat(result, hasStatus(401));
        assertThat(result, hasJsonBody(ErrorResponse.INVALID_LOGIN_CREDS));
        verify(authSessionService, never()).updateSession(any(AuthSessionItem.class));
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldIncrementRelevantCountWhenCredentialsAreInvalid(boolean isReauthJourney) {
        setupExistingUserInDatabase(EMAIL);
        usingApplicableUserCredentialsWithLogin(SMS, false);
        when(permissionDecisionManager.canReceivePassword(any(), any()))
                .thenReturn(Result.success(new Decision.Permitted(0)));

        usingValidAuthSession();

        var body = isReauthJourney ? validBodyWithReauthJourney : validBodyWithEmailAndPassword;

        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, body);
        handler.handleRequest(event, context);

        JourneyType expectedJourneyType =
                isReauthJourney ? JourneyType.REAUTHENTICATION : JourneyType.SIGN_IN;
        verify(userActionsManager, atLeastOnce())
                .incorrectPasswordReceived(eq(expectedJourneyType), any());
    }

    @Test
    void shouldReturn401IfMigratedUserHasInvalidCredentials() {
        String legacySubjectId = new Subject().getValue();
        UserProfile userProfile = generateUserProfile(legacySubjectId);
        setupUserInDatabase(EMAIL, userProfile);

        UserCredentials applicableUserCredentials = usingApplicableUserCredentials(AUTH_APP);

        when(userMigrationService.processMigratedUser(
                        applicableUserCredentials, CommonTestVariables.PASSWORD))
                .thenReturn(false);
        usingValidAuthSessionWithRequestedCredentialStrength(MEDIUM_LEVEL);

        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, validBodyWithEmailAndPassword);
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(401));
        assertThat(result, hasJsonBody(ErrorResponse.INVALID_LOGIN_CREDS));
        verifyNoInteractions(cloudwatchMetricsService);
        verify(authSessionService, never()).updateSession(any(AuthSessionItem.class));
    }

    @Test
    void shouldReturn400IfAnyRequestParametersAreMissing() {
        var bodyWithoutEmail = format("{ \"password\": \"%s\"}", CommonTestVariables.PASSWORD);
        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, bodyWithoutEmail);

        usingValidAuthSession();
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.REQUEST_MISSING_PARAMS));
        verify(authSessionService, never()).updateSession(any(AuthSessionItem.class));
    }

    @Test
    void shouldReturn400IfSessionIdIsInvalid() {
        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, validBodyWithEmailAndPassword);

        when(authSessionService.getSessionFromRequestHeaders(event.getHeaders()))
                .thenReturn(Optional.empty());

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.SESSION_ID_MISSING));
        verify(authSessionService, never()).updateSession(any(AuthSessionItem.class));
    }

    @Test
    void shouldReturn400IfNoAuthSessionPresent() {
        usingInvalidAuthSession();
        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, validBodyWithEmailAndPassword);

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.SESSION_ID_MISSING));
    }

    @Test
    void shouldReturn400IfUserDoesNotHaveAnAccount() {
        when(authenticationService.getUserProfileByEmailMaybe(EMAIL)).thenReturn(Optional.empty());
        usingValidAuthSession();

        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, validBodyWithEmailAndPassword);
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.AUTH_NO_ACCOUNT_WITH_EMAIL,
                        auditContextWithoutUserInfo.withTxmaAuditEncoded(ENCODED_DEVICE_DETAILS));

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ACCT_DOES_NOT_EXIST));
        verify(authSessionService, never()).updateSession(any(AuthSessionItem.class));
    }

    @Test
    void shouldReturn500IfFailedToGetMfaMethods() {
        setupExistingUserInDatabase(EMAIL);
        usingValidAuthSessionWithRequestedCredentialStrength(MEDIUM_LEVEL);
        usingApplicableUserCredentialsWithLogin(SMS, true);
        when(mfaMethodsService.getMfaMethods(EMAIL))
                .thenReturn(
                        Result.failure(
                                UNEXPECTED_ERROR_CREATING_MFA_IDENTIFIER_FOR_NON_MIGRATED_AUTH_APP));

        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, validBodyWithEmailAndPassword);
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(500));
        assertThat(result, hasJsonBody(ErrorResponse.AUTH_APP_MFA_ID_ERROR));
    }

    @Test
    void shouldReturn500IfFailedToConvertMfaMethodsForResponse() {
        setupExistingUserInDatabase(EMAIL);
        usingValidAuthSessionWithRequestedCredentialStrength(MEDIUM_LEVEL);
        usingApplicableUserCredentialsWithLogin(SMS, true);
        when(mfaMethodsService.getMfaMethods(EMAIL))
                .thenReturn(
                        Result.success(
                                List.of(
                                        new MFAMethod()
                                                .withMfaMethodType("invalid-type")
                                                .withMethodVerified(true)
                                                .withEnabled(true)
                                                .withDestination("phone-number")
                                                .withPriority(DEFAULT.name())
                                                .withMfaIdentifier("mfa-id"))));

        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, validBodyWithEmailAndPassword);
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(500));
        assertThat(result, hasJsonBody(ErrorResponse.MFA_METHODS_RETRIEVAL_ERROR));
    }

    @Test
    void shouldHandleErrorsRetrievingADefaultMethod() {
        MFAMethod mfaMethod =
                MFAMethod.smsMfaMethod(
                        true,
                        true,
                        CommonTestVariables.UK_MOBILE_NUMBER,
                        PriorityIdentifier.BACKUP,
                        "some-mfa-id");
        setupExistingUserInDatabase(EMAIL);
        var userCredentials =
                new UserCredentials()
                        .withEmail(EMAIL)
                        .withPassword(CommonTestVariables.PASSWORD)
                        .setMfaMethod(mfaMethod);
        when(authenticationService.getUserCredentialsFromEmail(EMAIL)).thenReturn(userCredentials);
        when(authenticationService.login(userCredentials, CommonTestVariables.PASSWORD))
                .thenReturn(true);
        when(mfaMethodsService.getMfaMethods(EMAIL)).thenReturn(Result.success(List.of(mfaMethod)));
        usingValidAuthSessionWithRequestedCredentialStrength(MEDIUM_LEVEL);

        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, validBodyWithEmailAndPassword);
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(200));

        assertThat(
                noDefaultMfaMethodLogging.events(),
                hasItem(
                        withMessageContaining(
                                "No default mfa method found for user. Is user migrated: unknown, user MFA method count: 1, MFA method priority-type pairs: (BACKUP,SMS).")));
        verifyInternalCommonSubjectIdentifierSaved();
    }

    @Test
    void shouldCallCorrectPasswordReceivedWhenLoginIsSuccessful() {
        setupExistingUserInDatabase(EMAIL);
        usingApplicableUserCredentialsWithLogin(SMS, true);
        usingValidAuthSession();

        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, validBodyWithEmailAndPassword);

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(200));
        verify(userActionsManager)
                .correctPasswordReceived(any(), argThat(pc -> pc.authSessionItem() != null));
    }

    private static Stream<MFAMethodType> validMfaMethods() {
        return Stream.of(AUTH_APP, SMS);
    }

    @ParameterizedTest
    @MethodSource("validMfaMethods")
    void shouldNotCheckForMFACodeBlocksOnA1FAJourney(MFAMethodType mfaMethodType) {
        setupExistingUserInDatabase(EMAIL);
        usingApplicableUserCredentialsWithLogin(mfaMethodType, true);
        usingValidAuthSessionWithRequestedCredentialStrength(LOW_LEVEL);

        // These should not affect the result of a low level journey
        when(permissionDecisionManager.canSendSmsOtpNotification(any(), any()))
                .thenReturn(Result.success(aTemporarilyLockedOutDecision));
        when(permissionDecisionManager.canVerifyMfaOtp(any(), any()))
                .thenReturn(Result.success(aTemporarilyLockedOutDecision));

        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, validBodyWithEmailAndPassword);
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(200));
    }

    private static Stream<Arguments> validMfaMethodsWithExpectedBlock() {
        return Stream.of(
                Arguments.of(
                        AUTH_APP,
                        CODE_BLOCKED_KEY_PREFIX + CodeRequestType.MFA_SIGN_IN,
                        ErrorResponse.TOO_MANY_INVALID_MFA_OTPS_ENTERED),
                Arguments.of(
                        AUTH_APP,
                        CODE_BLOCKED_KEY_PREFIX + AUTH_APP + "_SIGN_IN",
                        ErrorResponse.TOO_MANY_INVALID_MFA_OTPS_ENTERED),
                Arguments.of(
                        SMS,
                        CODE_BLOCKED_KEY_PREFIX + CodeRequestType.MFA_SIGN_IN,
                        ErrorResponse.TOO_MANY_INVALID_MFA_OTPS_ENTERED),
                Arguments.of(
                        SMS,
                        CODE_BLOCKED_KEY_PREFIX + SMS + "_SIGN_IN",
                        ErrorResponse.TOO_MANY_INVALID_MFA_OTPS_ENTERED),
                Arguments.of(
                        SMS,
                        CODE_REQUEST_BLOCKED_KEY_PREFIX + CodeRequestType.MFA_SIGN_IN,
                        ErrorResponse.BLOCKED_FOR_SENDING_MFA_OTPS),
                Arguments.of(
                        SMS,
                        CODE_REQUEST_BLOCKED_KEY_PREFIX + SMS + "_SIGN_IN",
                        ErrorResponse.BLOCKED_FOR_SENDING_MFA_OTPS));
    }

    @ParameterizedTest
    @MethodSource("validMfaMethodsWithExpectedBlock")
    void shouldReturn400ErrorWhenUserHasAnMFACodeBlock(
            MFAMethodType mfaMethodType, String blockKeyPrefix, ErrorResponse expectedError) {
        setupExistingUserInDatabase(EMAIL);
        usingValidAuthSessionWithRequestedCredentialStrength(MEDIUM_LEVEL);
        usingApplicableUserCredentialsWithLogin(mfaMethodType, true);

        if (expectedError == ErrorResponse.BLOCKED_FOR_SENDING_MFA_OTPS) {
            when(permissionDecisionManager.canSendSmsOtpNotification(any(), any()))
                    .thenReturn(Result.success(aTemporarilyLockedOutDecision));
            when(permissionDecisionManager.canVerifyMfaOtp(any(), any()))
                    .thenReturn(Result.success(new Decision.Permitted(0)));
        } else {
            when(permissionDecisionManager.canSendSmsOtpNotification(any(), any()))
                    .thenReturn(Result.success(new Decision.Permitted(0)));
            when(permissionDecisionManager.canVerifyMfaOtp(any(), any()))
                    .thenReturn(Result.success(aTemporarilyLockedOutDecision));
        }

        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, validBodyWithEmailAndPassword);
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(expectedError));
    }

    @Test
    void shouldReturn400ErrorWhenUserIsIndefinitelyLockedOutFromSendingSmsOtp() {
        setupExistingUserInDatabase(EMAIL);
        usingValidAuthSessionWithRequestedCredentialStrength(MEDIUM_LEVEL);
        usingApplicableUserCredentialsWithLogin(SMS, true);

        when(permissionDecisionManager.canSendSmsOtpNotification(any(), any()))
                .thenReturn(
                        Result.success(
                                new Decision.IndefinitelyLockedOut(
                                        ForbiddenReason.EXCEEDED_SEND_MFA_OTP_NOTIFICATION_LIMIT,
                                        10)));
        when(permissionDecisionManager.canVerifyMfaOtp(any(), any()))
                .thenReturn(Result.success(new Decision.Permitted(0)));

        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, validBodyWithEmailAndPassword);
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.INDEFINITELY_BLOCKED_SENDING_INT_NUMBERS_SMS));

        var permissionContextCaptor = ArgumentCaptor.forClass(PermissionContext.class);
        verify(permissionDecisionManager)
                .canSendSmsOtpNotification(any(), permissionContextCaptor.capture());
        assertEquals(
                Optional.of(CommonTestVariables.UK_MOBILE_NUMBER),
                permissionContextCaptor.getValue().e164FormattedPhoneNumber());
    }

    @Test
    void shouldSetIsPartiallyCreatedAccountTrueWhenMfaMethodNotVerified() {
        var userProfile =
                generateUserProfile(null).withPhoneNumberVerified(false).withPhoneNumber(null);
        setupUserInDatabase(EMAIL, userProfile);
        var userCredentialsNoMfa =
                new UserCredentials().withEmail(EMAIL).withPassword(CommonTestVariables.PASSWORD);
        when(authenticationService.login(userCredentialsNoMfa, CommonTestVariables.PASSWORD))
                .thenReturn(true);
        when(authenticationService.getUserCredentialsFromEmail(EMAIL))
                .thenReturn(userCredentialsNoMfa);
        when(mfaMethodsService.getMfaMethods(EMAIL)).thenReturn(Result.success(List.of()));
        usingValidAuthSessionWithRequestedCredentialStrength(MEDIUM_LEVEL);

        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, validBodyWithEmailAndPassword);
        handler.handleRequest(event, context);

        verify(authSessionService).updateSession(argThat(s -> s.getIsPartiallyCreatedAccount()));
    }

    @Test
    void shouldSetIsPartiallyCreatedAccountFalseWhenMfaMethodVerified() {
        setupExistingUserInDatabase(EMAIL);
        usingApplicableUserCredentialsWithLogin(SMS, true);
        usingValidAuthSessionWithRequestedCredentialStrength(MEDIUM_LEVEL);

        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, validBodyWithEmailAndPassword);
        handler.handleRequest(event, context);

        verify(authSessionService).updateSession(argThat(s -> !s.getIsPartiallyCreatedAccount()));
    }

    @Nested
    class PasswordRehashing {
        @Test
        void shouldRehashPasswordWhenFlagEnabledAndParamsDiffer() {
            when(configurationService.isPasswordRehashOnLoginEnabled()).thenReturn(true);

            when(configurationService.getArgon2MemoryInKibibytes()).thenReturn(32768);
            when(configurationService.getArgon2Iterations()).thenReturn(2);
            when(configurationService.getArgon2Parallelism()).thenReturn(1);
            var password = "$argon2id$v=19$m=15360,t=2,p=1$c29tZXNhbHRieXRlcw$dGVzdGhhc2hieXRlcw";
            setupUserWhoCanSuccessfullyLoginWithPassword(password);

            var event =
                    apiRequestEventWithHeadersAndBody(VALID_HEADERS, validBodyWithEmailAndPassword);
            handler.handleRequest(event, context);

            verify(authenticationService).updatePassword(EMAIL, CommonTestVariables.PASSWORD);
        }

        @Test
        void shouldNotRehashPasswordWhenFlagEnabledButParamsMatch() {
            when(configurationService.isPasswordRehashOnLoginEnabled()).thenReturn(true);

            when(configurationService.getArgon2MemoryInKibibytes()).thenReturn(15360);
            when(configurationService.getArgon2Iterations()).thenReturn(2);
            when(configurationService.getArgon2Parallelism()).thenReturn(1);
            var password = "$argon2id$v=19$m=15360,t=2,p=1$c29tZXNhbHRieXRlcw$dGVzdGhhc2hieXRlcw";
            setupUserWhoCanSuccessfullyLoginWithPassword(password);

            var event =
                    apiRequestEventWithHeadersAndBody(VALID_HEADERS, validBodyWithEmailAndPassword);
            handler.handleRequest(event, context);

            verify(authenticationService, never()).updatePassword(anyString(), anyString());
        }

        @Test
        void shouldStillLoginSuccessfullyWhenRehashThrowsException() {
            when(configurationService.isPasswordRehashOnLoginEnabled()).thenReturn(true);

            when(configurationService.getArgon2MemoryInKibibytes()).thenReturn(32768);
            when(configurationService.getArgon2Iterations()).thenReturn(2);
            when(configurationService.getArgon2Parallelism()).thenReturn(1);
            var password = "$argon2id$v=19$m=15360,t=2,p=1$c29tZXNhbHRieXRlcw$dGVzdGhhc2hieXRlcw";
            setupUserWhoCanSuccessfullyLoginWithPassword(password);

            doThrow(new RuntimeException("DynamoDB error"))
                    .when(authenticationService)
                    .updatePassword(anyString(), anyString());

            var event =
                    apiRequestEventWithHeadersAndBody(VALID_HEADERS, validBodyWithEmailAndPassword);
            var result = handler.handleRequest(event, context);

            assertThat(result, hasStatus(200));
        }

        @Test
        void shouldNotRehashPasswordWhenFlagDisabled() {
            when(configurationService.isPasswordRehashOnLoginEnabled()).thenReturn(false);

            usingApplicableUserCredentialsWithLogin(SMS, true);

            var event =
                    apiRequestEventWithHeadersAndBody(VALID_HEADERS, validBodyWithEmailAndPassword);
            handler.handleRequest(event, context);

            verify(authenticationService, never()).updatePassword(anyString(), anyString());
        }

        private void setupUserWhoCanSuccessfullyLoginWithPassword(String password) {
            setupExistingUserInDatabase(EMAIL);
            when(mfaMethodsService.getMfaMethods(EMAIL))
                    .thenReturn(Result.success(List.of(DEFAULT_SMS_MFA_METHOD)));
            usingValidAuthSessionWithRequestedCredentialStrength(MEDIUM_LEVEL);
            var userCredentials = new UserCredentials().withEmail(EMAIL).withPassword(password);
            when(authenticationService.getUserCredentialsFromEmail(EMAIL))
                    .thenReturn(userCredentials);
            when(authenticationService.login(eq(userCredentials), anyString())).thenReturn(true);
        }
    }

    private void usingValidAuthSessionWithAchievedCredentialStrength(
            CredentialTrustLevel credentialTrustLevel) {
        usingValidAuthSessionWithAchievedAndRequestedCredentialStrength(
                credentialTrustLevel, CredentialTrustLevel.MEDIUM_LEVEL);
    }

    private void usingValidAuthSessionWithRequestedCredentialStrength(
            CredentialTrustLevel credentialTrustLevel) {
        usingValidAuthSessionWithAchievedAndRequestedCredentialStrength(null, credentialTrustLevel);
    }

    private void usingValidAuthSessionWithAchievedAndRequestedCredentialStrength(
            CredentialTrustLevel achievedCredentialStrength,
            CredentialTrustLevel requestedCredentialStrength) {
        when(authSessionService.getSessionFromRequestHeaders(anyMap()))
                .thenReturn(
                        Optional.of(
                                new AuthSessionItem()
                                        .withSessionId(SESSION_ID)
                                        .withEmailAddress(EMAIL)
                                        .withAccountState(AuthSessionItem.AccountState.UNKNOWN)
                                        .withClientId(CLIENT_ID.getValue())
                                        .withAchievedCredentialStrength(achievedCredentialStrength)
                                        .withRequestedCredentialStrength(
                                                requestedCredentialStrength)
                                        .withClientName(CLIENT_NAME)
                                        .withRpSectorIdentifierHost(SECTOR_IDENTIFIER_HOST)));
    }

    private void usingValidAuthSessionInSmokeTest() {
        when(authSessionService.getSessionFromRequestHeaders(anyMap()))
                .thenReturn(
                        Optional.of(
                                new AuthSessionItem()
                                        .withSessionId(SESSION_ID)
                                        .withEmailAddress(EMAIL)
                                        .withAccountState(AuthSessionItem.AccountState.UNKNOWN)
                                        .withClientId(CLIENT_ID.getValue())
                                        .withRequestedCredentialStrength(MEDIUM_LEVEL)
                                        .withIsSmokeTest(true)
                                        .withRpSectorIdentifierHost(SECTOR_IDENTIFIER_HOST)));
    }

    private void usingValidAuthSession() {
        usingValidAuthSessionWithAchievedCredentialStrength(null);
    }

    private void usingInvalidAuthSession() {
        when(authSessionService.getSessionFromRequestHeaders(anyMap()))
                .thenReturn(Optional.empty());
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
        when(mfaMethodsService.getMfaMethods(EMAIL))
                .thenReturn(
                        Result.success(
                                List.of(
                                        mfaMethodType.equals(AUTH_APP)
                                                ? DEFAULT_AUTH_APP_MFA_METHOD
                                                : DEFAULT_SMS_MFA_METHOD)));
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

    private void verifyInternalCommonSubjectIdentifierSaved() {
        verify(authSessionService, atLeastOnce())
                .updateSession(
                        argThat(t -> t.getInternalCommonSubjectId().equals(expectedCommonSubject)));
    }

    private UserProfile setupExistingUserInDatabase(String email) {
        var userProfile = generateUserProfile(null);
        setupUserInDatabase(email, userProfile);
        return userProfile;
    }

    private void setupUserInDatabase(String email, UserProfile userProfile) {
        when(authenticationService.getUserProfileByEmailMaybe(email))
                .thenReturn(Optional.of(userProfile));
    }
}
