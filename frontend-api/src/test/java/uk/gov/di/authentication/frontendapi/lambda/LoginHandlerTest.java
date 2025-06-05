package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
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
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.CredentialTrustLevel;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.PriorityIdentifier;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.TermsAndConditions;
import uk.gov.di.authentication.shared.entity.UserCredentials;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethod;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.helpers.CommonTestVariables;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.helpers.SaltHelper;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthSessionService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.CommonPasswordsService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.SerializationService;
import uk.gov.di.authentication.shared.services.SessionService;
import uk.gov.di.authentication.shared.services.mfa.MFAMethodsService;
import uk.gov.di.authentication.shared.services.permissions.UserPermissionService;
import uk.gov.di.authentication.sharedtest.logging.CaptureLoggingExtension;

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
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
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
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.CLIENT_SESSION_ID;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.DI_PERSISTENT_SESSION_ID;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.ENCODED_DEVICE_DETAILS;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.IP_ADDRESS;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.SESSION_ID;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.VALID_HEADERS;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.VALID_HEADERS_WITHOUT_AUDIT_ENCODED;
import static uk.gov.di.authentication.shared.services.AuditService.MetadataPair.pair;
import static uk.gov.di.authentication.shared.services.mfa.MfaRetrieveFailureReason.UNEXPECTED_ERROR_CREATING_MFA_IDENTIFIER_FOR_NON_MIGRATED_AUTH_APP;
import static uk.gov.di.authentication.sharedtest.logging.LogEventMatcher.withMessageContaining;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class LoginHandlerTest {

    private static final String EMAIL = CommonTestVariables.EMAIL;
    private static final String INTERNAL_SECTOR_URI = "https://test.account.gov.uk";
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
    private static final Session session = new Session();
    private LoginHandler handler;
    private final Context context = mock(Context.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final UserPermissionService userPermissionService = mock(UserPermissionService.class);
    private final AuthenticationService authenticationService = mock(AuthenticationService.class);
    private final CodeStorageService codeStorageService = mock(CodeStorageService.class);
    private final SessionService sessionService = mock(SessionService.class);
    private final ClientService clientService = mock(ClientService.class);
    private final UserMigrationService userMigrationService = mock(UserMigrationService.class);
    private final AuditService auditService = mock(AuditService.class);
    private final CloudwatchMetricsService cloudwatchMetricsService =
            mock(CloudwatchMetricsService.class);
    private final CommonPasswordsService commonPasswordsService =
            mock(CommonPasswordsService.class);
    private final AuthSessionService authSessionService = mock(AuthSessionService.class);
    private final MFAMethodsService mfaMethodsService = mock(MFAMethodsService.class);
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
                    Optional.empty());

    private final AuditContext auditContextWithoutUserInfo =
            auditContextWithAllUserInfo
                    .withSubjectId(AuditService.UNKNOWN)
                    .withPhoneNumber(AuditService.UNKNOWN);

    @RegisterExtension
    private final CaptureLoggingExtension logging = new CaptureLoggingExtension(LoginHandler.class);

    @AfterEach
    void tearDown() {
        assertThat(logging.events(), not(hasItem(withMessageContaining(SESSION_ID))));
    }

    @BeforeEach
    void setUp() {
        when(configurationService.getMaxPasswordRetries()).thenReturn(MAX_ALLOWED_PASSWORD_RETRIES);
        when(configurationService.getTermsAndConditionsVersion()).thenReturn("1.0");
        when(context.getAwsRequestId()).thenReturn("aws-session-id");
        when(clientService.getClient(CLIENT_ID.getValue()))
                .thenReturn(Optional.of(generateClientRegistry()));
        when(configurationService.getInternalSectorUri()).thenReturn(INTERNAL_SECTOR_URI);
        when(authenticationService.getOrGenerateSalt(any(UserProfile.class))).thenReturn(SALT);
        handler =
                new LoginHandler(
                        configurationService,
                        sessionService,
                        authenticationService,
                        clientService,
                        codeStorageService,
                        userMigrationService,
                        auditService,
                        cloudwatchMetricsService,
                        commonPasswordsService,
                        userPermissionService,
                        authSessionService,
                        mfaMethodsService);
    }

    @Test
    void shouldReturn200IfLoginIsSuccessfulAndMfaNotRequired() throws Json.JsonException {
        // Arrange
        UserProfile userProfile = generateUserProfile(null);
        when(authenticationService.getUserProfileByEmailMaybe(EMAIL))
                .thenReturn(Optional.of(userProfile));

        usingValidSession();
        usingApplicableUserCredentialsWithLogin(SMS, true);
        usingValidAuthSessionWithRequestedCredentialStrength(LOW_LEVEL);

        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, validBodyWithEmailAndPassword);

        // Act
        var result = handler.handleRequest(event, context);

        // Assert
        assertThat(result, hasStatus(200));

        LoginResponse response = objectMapper.readValue(result.getBody(), LoginResponse.class);

        assertThat(
                response.redactedPhoneNumber(),
                equalTo(redactPhoneNumber(CommonTestVariables.UK_MOBILE_NUMBER)));
        assertThat(response.latestTermsAndConditionsAccepted(), equalTo(true));

        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.AUTH_LOG_IN_SUCCESS,
                        auditContextWithAllUserInfo.withTxmaAuditEncoded(
                                Optional.of(ENCODED_DEVICE_DETAILS)),
                        pair("internalSubjectId", INTERNAL_SUBJECT_ID.getValue()));

        verify(cloudwatchMetricsService)
                .incrementAuthenticationSuccess(
                        AuthSessionItem.AccountState.EXISTING,
                        CLIENT_ID.getValue(),
                        CLIENT_NAME,
                        "P0",
                        false,
                        false);

        verifyInternalCommonSubjectIdentifierSaved();
    }

    @Test
    void shouldSetAchievedCredentialTrustLowWhenMfaNotRequiredAndNoPreviousValue()
            throws Json.JsonException {
        // Arrange
        UserProfile userProfile = generateUserProfile(null);
        when(authenticationService.getUserProfileByEmailMaybe(EMAIL))
                .thenReturn(Optional.of(userProfile));

        usingValidSession();
        usingApplicableUserCredentialsWithLogin(SMS, true);
        usingValidAuthSessionWithRequestedCredentialStrength(LOW_LEVEL);

        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, validBodyWithEmailAndPassword);

        // Act
        var result = handler.handleRequest(event, context);

        // Assert
        assertThat(result, hasStatus(200));

        LoginResponse response = objectMapper.readValue(result.getBody(), LoginResponse.class);

        assertThat(
                response.redactedPhoneNumber(),
                equalTo(redactPhoneNumber(CommonTestVariables.UK_MOBILE_NUMBER)));
        assertThat(response.latestTermsAndConditionsAccepted(), equalTo(true));

        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.AUTH_LOG_IN_SUCCESS,
                        auditContextWithAllUserInfo.withTxmaAuditEncoded(
                                Optional.of(ENCODED_DEVICE_DETAILS)),
                        pair("internalSubjectId", INTERNAL_SUBJECT_ID.getValue()));

        verify(cloudwatchMetricsService)
                .incrementAuthenticationSuccess(
                        AuthSessionItem.AccountState.EXISTING,
                        CLIENT_ID.getValue(),
                        CLIENT_NAME,
                        "P0",
                        false,
                        false);

        verify(authSessionService)
                .updateSession(
                        argThat(
                                as ->
                                        as.getAchievedCredentialStrength() == LOW_LEVEL
                                                && as.getIsNewAccount()
                                                        == AuthSessionItem.AccountState.EXISTING));
        verifyInternalCommonSubjectIdentifierSaved();
    }

    @Test
    void shouldRetainPreviouslyMediumCredentialTrustWhenOnLowLevelJourney()
            throws Json.JsonException {
        // Arrange
        UserProfile userProfile = generateUserProfile(null);
        when(authenticationService.getUserProfileByEmailMaybe(EMAIL))
                .thenReturn(Optional.of(userProfile));

        usingValidSession();
        usingApplicableUserCredentialsWithLogin(SMS, true);
        usingValidAuthSessionWithAchievedAndRequestedCredentialStrength(MEDIUM_LEVEL, LOW_LEVEL);

        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, validBodyWithEmailAndPassword);

        // Act
        var result = handler.handleRequest(event, context);

        // Assert
        assertThat(result, hasStatus(200));

        LoginResponse response = objectMapper.readValue(result.getBody(), LoginResponse.class);

        assertThat(
                response.redactedPhoneNumber(),
                equalTo(redactPhoneNumber(CommonTestVariables.UK_MOBILE_NUMBER)));
        assertThat(response.latestTermsAndConditionsAccepted(), equalTo(true));

        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.AUTH_LOG_IN_SUCCESS,
                        auditContextWithAllUserInfo.withTxmaAuditEncoded(
                                Optional.of(ENCODED_DEVICE_DETAILS)),
                        pair("internalSubjectId", INTERNAL_SUBJECT_ID.getValue()));

        verify(cloudwatchMetricsService)
                .incrementAuthenticationSuccess(
                        AuthSessionItem.AccountState.EXISTING,
                        CLIENT_ID.getValue(),
                        CLIENT_NAME,
                        "P0",
                        false,
                        false);

        verify(authSessionService)
                .updateSession(
                        argThat(
                                as ->
                                        as.getAchievedCredentialStrength() == MEDIUM_LEVEL
                                                && as.getIsNewAccount()
                                                        == AuthSessionItem.AccountState.EXISTING));
        verifyInternalCommonSubjectIdentifierSaved();
    }

    @Test
    void shouldRetainLowCredentialTrustLevelWhenPreviouslyObtained() throws Json.JsonException {
        // Arrange
        UserProfile userProfile = generateUserProfile(null);
        when(authenticationService.getUserProfileByEmailMaybe(EMAIL))
                .thenReturn(Optional.of(userProfile));

        usingValidSession();
        usingApplicableUserCredentialsWithLogin(SMS, true);
        usingValidAuthSessionWithAchievedAndRequestedCredentialStrength(LOW_LEVEL, LOW_LEVEL);

        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, validBodyWithEmailAndPassword);

        // Act
        var result = handler.handleRequest(event, context);

        // Assert
        assertThat(result, hasStatus(200));

        LoginResponse response = objectMapper.readValue(result.getBody(), LoginResponse.class);

        assertThat(
                response.redactedPhoneNumber(),
                equalTo(redactPhoneNumber(CommonTestVariables.UK_MOBILE_NUMBER)));
        assertThat(response.latestTermsAndConditionsAccepted(), equalTo(true));

        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.AUTH_LOG_IN_SUCCESS,
                        auditContextWithAllUserInfo.withTxmaAuditEncoded(
                                Optional.of(ENCODED_DEVICE_DETAILS)),
                        pair("internalSubjectId", INTERNAL_SUBJECT_ID.getValue()));

        verify(cloudwatchMetricsService)
                .incrementAuthenticationSuccess(
                        AuthSessionItem.AccountState.EXISTING,
                        CLIENT_ID.getValue(),
                        CLIENT_NAME,
                        "P0",
                        false,
                        false);

        verify(authSessionService)
                .updateSession(
                        argThat(
                                as ->
                                        as.getAchievedCredentialStrength() == LOW_LEVEL
                                                && as.getIsNewAccount()
                                                        == AuthSessionItem.AccountState.EXISTING));
        verifyInternalCommonSubjectIdentifierSaved();
    }

    @Test
    void checkAuditEventStillEmittedWhenTICFHeaderNotProvided() throws Json.JsonException {
        UserProfile userProfile = generateUserProfile(null);
        when(authenticationService.getUserProfileByEmailMaybe(EMAIL))
                .thenReturn(Optional.of(userProfile));

        usingValidSession();
        usingValidAuthSessionWithRequestedCredentialStrength(LOW_LEVEL);
        usingApplicableUserCredentialsWithLogin(SMS, true);

        var event =
                apiRequestEventWithHeadersAndBody(
                        VALID_HEADERS_WITHOUT_AUDIT_ENCODED, validBodyWithEmailAndPassword);

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(200));

        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.AUTH_LOG_IN_SUCCESS,
                        auditContextWithAllUserInfo,
                        pair("internalSubjectId", INTERNAL_SUBJECT_ID.getValue()));
    }

    @ParameterizedTest
    @EnumSource(MFAMethodType.class)
    void shouldReturn200IfLoginIsSuccessfulAndMfaIsRequired(MFAMethodType mfaMethodType) {
        UserProfile userProfile = generateUserProfile(null);
        when(authenticationService.getUserProfileByEmailMaybe(EMAIL))
                .thenReturn(Optional.of(userProfile));
        usingValidSession();
        usingValidAuthSessionWithRequestedCredentialStrength(MEDIUM_LEVEL);
        usingApplicableUserCredentialsWithLogin(mfaMethodType, true);

        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, validBodyWithEmailAndPassword);
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(200));

        verifyNoInteractions(cloudwatchMetricsService);

        verifyInternalCommonSubjectIdentifierSaved();
    }

    @ParameterizedTest
    @EnumSource(MFAMethodType.class)
    void shouldReturn200IfLoginIsSuccessfulAndTermsAndConditionsNotAccepted(
            MFAMethodType mfaMethodType) throws Json.JsonException {
        when(configurationService.getTermsAndConditionsVersion()).thenReturn("2.0");
        UserProfile userProfile = generateUserProfile(null);
        when(authenticationService.getUserProfileByEmailMaybe(EMAIL))
                .thenReturn(Optional.of(userProfile));
        usingValidSession();
        usingValidAuthSession();
        usingApplicableUserCredentialsWithLogin(mfaMethodType, true);

        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, validBodyWithEmailAndPassword);
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(200));

        LoginResponse response = objectMapper.readValue(result.getBody(), LoginResponse.class);

        assertThat(response.latestTermsAndConditionsAccepted(), equalTo(false));

        verifyNoInteractions(cloudwatchMetricsService);
        verifyInternalCommonSubjectIdentifierSaved();
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
        var userProfile = generateUserProfile(null);
        var userCredentials =
                new UserCredentials()
                        .withEmail(EMAIL)
                        .withPassword(CommonTestVariables.PASSWORD)
                        .setMfaMethod(mfaMethod);
        when(authenticationService.login(userCredentials, CommonTestVariables.PASSWORD))
                .thenReturn(true);
        when(authenticationService.getUserProfileByEmailMaybe(EMAIL))
                .thenReturn(Optional.of(userProfile));
        when(authenticationService.getUserCredentialsFromEmail(EMAIL)).thenReturn(userCredentials);
        when(mfaMethodsService.getMfaMethods(EMAIL)).thenReturn(Result.success(List.of(mfaMethod)));
        usingValidSession();
        usingValidAuthSessionWithRequestedCredentialStrength(MEDIUM_LEVEL);

        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, validBodyWithEmailAndPassword);
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(200));

        var response = objectMapper.readValue(result.getBody(), LoginResponse.class);
        assertThat(response.mfaMethodType(), equalTo(SMS));
        assertThat(response.mfaMethodVerified(), equalTo(true));

        verifyNoInteractions(cloudwatchMetricsService);

        verifyInternalCommonSubjectIdentifierSaved();
    }

    private static Stream<Arguments> migratedMfaMethodsToExpectedLoginResponse() {
        var expectedRedactedPhoneNumber = redactPhoneNumber(CommonTestVariables.UK_MOBILE_NUMBER);
        return Stream.of(
                Arguments.of(
                        DEFAULT_SMS_MFA_METHOD,
                        new LoginResponse(
                                expectedRedactedPhoneNumber,
                                true,
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
        var migratedUserCredentials =
                new UserCredentials()
                        .withEmail(EMAIL)
                        .withPassword(CommonTestVariables.PASSWORD)
                        .setMfaMethod(mfaMethod);

        when(authenticationService.login(migratedUserCredentials, CommonTestVariables.PASSWORD))
                .thenReturn(true);
        when(authenticationService.getUserProfileByEmailMaybe(EMAIL))
                .thenReturn(Optional.of(userProfile));
        when(authenticationService.getUserCredentialsFromEmail(EMAIL))
                .thenReturn(migratedUserCredentials);
        when(mfaMethodsService.getMfaMethods(EMAIL)).thenReturn(Result.success(List.of(mfaMethod)));
        usingValidSession();
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
        // Arrange
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
        var testUserCredentials =
                new UserCredentials()
                        .withEmail(EMAIL)
                        .withPassword(CommonTestVariables.PASSWORD)
                        .setMfaMethod(mfaMethods.get(0));

        when(authenticationService.login(testUserCredentials, CommonTestVariables.PASSWORD))
                .thenReturn(true);
        when(authenticationService.getUserProfileByEmailMaybe(EMAIL))
                .thenReturn(Optional.of(testUserProfile));
        when(authenticationService.getUserCredentialsFromEmail(EMAIL))
                .thenReturn(testUserCredentials);
        when(mfaMethodsService.getMfaMethods(EMAIL)).thenReturn(Result.success(mfaMethods));
        usingValidSession();
        usingValidAuthSessionWithRequestedCredentialStrength(MEDIUM_LEVEL);

        // Act
        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, validBodyWithEmailAndPassword);
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        // Assert
        assertThat(result, hasStatus(200));

        var response = objectMapper.readValue(result.getBody(), LoginResponse.class);
        assertEquals(expectedResponse, response);
    }

    @ParameterizedTest
    @EnumSource(MFAMethodType.class)
    void shouldReturn200IfLoginIsSuccessfulButPasswordWasCommonPassword(MFAMethodType mfaMethodType)
            throws Json.JsonException {
        when(commonPasswordsService.isCommonPassword(anyString())).thenReturn(true);
        UserProfile userProfile = generateUserProfile(null);
        when(authenticationService.getUserProfileByEmailMaybe(EMAIL))
                .thenReturn(Optional.of(userProfile));
        usingValidSession();
        usingValidAuthSession();
        usingApplicableUserCredentialsWithLogin(mfaMethodType, true);

        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, validBodyWithEmailAndPassword);
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);
        assertThat(result, hasStatus(200));

        LoginResponse response = objectMapper.readValue(result.getBody(), LoginResponse.class);
        assertThat(response.passwordChangeRequired(), equalTo(true));
        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.AUTH_LOG_IN_SUCCESS,
                        auditContextWithAllUserInfo.withTxmaAuditEncoded(
                                Optional.of(ENCODED_DEVICE_DETAILS)),
                        pair("internalSubjectId", INTERNAL_SUBJECT_ID.getValue()),
                        pair("passwordResetType", PasswordResetType.FORCED_WEAK_PASSWORD));
        verifyNoInteractions(cloudwatchMetricsService);
        verifyInternalCommonSubjectIdentifierSaved();
    }

    @ParameterizedTest
    @EnumSource(MFAMethodType.class)
    void shouldReturn200IfMigratedUserHasBeenProcessesSuccessfully(MFAMethodType mfaMethodType)
            throws Json.JsonException {
        String legacySubjectId = new Subject().getValue();
        UserProfile userProfile = generateUserProfile(legacySubjectId);
        when(authenticationService.getUserProfileByEmailMaybe(EMAIL))
                .thenReturn(Optional.of(userProfile));
        UserCredentials applicableUserCredentials =
                usingApplicableUserCredentialsWithLogin(mfaMethodType, false);
        applicableUserCredentials.withPassword(null);
        when(userMigrationService.processMigratedUser(
                        applicableUserCredentials, CommonTestVariables.PASSWORD))
                .thenReturn(true);
        usingValidSession();
        usingValidAuthSession();

        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, validBodyWithEmailAndPassword);
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(200));

        LoginResponse response = objectMapper.readValue(result.getBody(), LoginResponse.class);
        assertThat(response.latestTermsAndConditionsAccepted(), equalTo(true));

        verifyNoInteractions(cloudwatchMetricsService);
        verifyInternalCommonSubjectIdentifierSaved();
    }

    @ParameterizedTest
    @EnumSource(MFAMethodType.class)
    void shouldChangeStateToAccountTemporarilyLockedAfterAttemptsReachMaxRetries(
            MFAMethodType mfaMethodType) {
        UserProfile userProfile = generateUserProfile(null);
        when(authenticationService.getUserProfileByEmailMaybe(EMAIL))
                .thenReturn(Optional.of(userProfile));

        var maxRetriesAllowed = configurationService.getMaxPasswordRetries();
        when(codeStorageService.getIncorrectPasswordCount(EMAIL)).thenReturn(maxRetriesAllowed - 1);
        usingValidSession();
        usingValidAuthSession();
        usingApplicableUserCredentialsWithLogin(mfaMethodType, false);

        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, validBodyWithEmailAndPassword);
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));

        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1028));
        verifyNoInteractions(cloudwatchMetricsService);
        verify(authSessionService, never()).updateSession(any(AuthSessionItem.class));
        verify(codeStorageService).getIncorrectPasswordCount(EMAIL);
        verify(codeStorageService).deleteIncorrectPasswordCount(EMAIL);
        verify(codeStorageService).saveBlockedForEmail(any(), any(), anyLong());

        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.AUTH_ACCOUNT_TEMPORARILY_LOCKED,
                        auditContextWithAllUserInfo.withTxmaAuditEncoded(
                                Optional.of(ENCODED_DEVICE_DETAILS)),
                        pair("internalSubjectId", userProfile.getSubjectID()),
                        pair("attemptNoFailedAt", maxRetriesAllowed),
                        pair("number_of_attempts_user_allowed_to_login", maxRetriesAllowed));
    }

    @ParameterizedTest
    @EnumSource(MFAMethodType.class)
    void
            shouldReturnErrorNotLockUserAccountAndRetainCountsOutAfterMaxNumberOfIncorrectPasswordsPresentedDuringReauthJourney(
                    MFAMethodType mfaMethodType) {
        UserProfile userProfile = generateUserProfile(null);
        when(authenticationService.getUserProfileByEmailMaybe(EMAIL))
                .thenReturn(Optional.of(userProfile));
        var maxRetriesAllowed = configurationService.getMaxPasswordRetries();
        when(codeStorageService.getIncorrectPasswordCountReauthJourney(EMAIL))
                .thenReturn(maxRetriesAllowed - 1);
        when(configurationService.supportReauthSignoutEnabled()).thenReturn(true);

        usingValidSession();
        usingValidAuthSession();
        usingApplicableUserCredentialsWithLogin(mfaMethodType, false);

        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, validBodyWithReauthJourney);

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1028));

        verify(codeStorageService).getIncorrectPasswordCountReauthJourney(EMAIL);
        verify(codeStorageService, never()).deleteIncorrectPasswordCountReauthJourney(EMAIL);
        verify(codeStorageService, never()).saveBlockedForEmail(any(), any(), anyLong());

        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.AUTH_INVALID_CREDENTIALS,
                        auditContextWithAllUserInfo.withTxmaAuditEncoded(
                                Optional.of(ENCODED_DEVICE_DETAILS)),
                        pair("internalSubjectId", userProfile.getSubjectID()),
                        pair(
                                "incorrectPasswordCount",
                                configurationService.getMaxPasswordRetries()),
                        pair("attemptNoFailedAt", configurationService.getMaxPasswordRetries()));

        verifyNoInteractions(cloudwatchMetricsService);
        verify(authSessionService, never()).updateSession(any(AuthSessionItem.class));
    }

    @ParameterizedTest
    @EnumSource(MFAMethodType.class)
    void shouldKeepUserLockedWhenTheyEnterSuccessfulLoginRequestInNewSession(
            MFAMethodType mfaMethodType) {
        UserProfile userProfile = generateUserProfile(null);
        when(authenticationService.getUserProfileByEmailMaybe(EMAIL))
                .thenReturn(Optional.of(userProfile));
        when(codeStorageService.getIncorrectPasswordCount(EMAIL))
                .thenReturn(MAX_ALLOWED_PASSWORD_RETRIES);
        when(codeStorageService.isBlockedForEmail(any(), any())).thenReturn(true);
        usingValidSession();
        usingValidAuthSession();
        usingApplicableUserCredentialsWithLogin(mfaMethodType, true);

        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, validBodyWithEmailAndPassword);

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1028));

        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.AUTH_ACCOUNT_TEMPORARILY_LOCKED,
                        auditContextWithAllUserInfo.withTxmaAuditEncoded(
                                Optional.of(ENCODED_DEVICE_DETAILS)),
                        pair("internalSubjectId", INTERNAL_SUBJECT_ID.getValue()),
                        pair("attemptNoFailedAt", configurationService.getMaxPasswordRetries()),
                        pair(
                                "number_of_attempts_user_allowed_to_login",
                                configurationService.getMaxPasswordRetries()));

        verifyNoInteractions(cloudwatchMetricsService);
        verify(authSessionService, never()).updateSession(any(AuthSessionItem.class));
    }

    @ParameterizedTest
    @EnumSource(MFAMethodType.class)
    void shouldRemoveIncorrectPasswordCountRemovesUponSuccessfulLogin(MFAMethodType mfaMethodType) {
        UserProfile userProfile = generateUserProfile(null);
        when(authenticationService.getUserProfileByEmailMaybe(EMAIL))
                .thenReturn(Optional.of(userProfile));
        UserCredentials applicableUserCredentials = usingApplicableUserCredentials(mfaMethodType);
        when(mfaMethodsService.getMfaMethods(EMAIL))
                .thenReturn(
                        Result.success(
                                List.of(
                                        mfaMethodType.equals(AUTH_APP)
                                                ? DEFAULT_AUTH_APP_MFA_METHOD
                                                : DEFAULT_SMS_MFA_METHOD)));
        when(codeStorageService.getIncorrectPasswordCount(EMAIL)).thenReturn(4);
        usingValidSession();
        usingValidAuthSession();

        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, validBodyWithEmailAndPassword);
        handler.handleRequest(event, context);

        when(authenticationService.login(applicableUserCredentials, CommonTestVariables.PASSWORD))
                .thenReturn(true);

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(200));
        verifyNoInteractions(cloudwatchMetricsService);
        verifyInternalCommonSubjectIdentifierSaved();
    }

    @ParameterizedTest
    @EnumSource(MFAMethodType.class)
    void shouldReturn401IfUserHasInvalidCredentials(MFAMethodType mfaMethodType) {
        UserProfile userProfile = generateUserProfile(null);
        when(authenticationService.getUserProfileByEmailMaybe(EMAIL))
                .thenReturn(Optional.of(userProfile));
        usingApplicableUserCredentialsWithLogin(mfaMethodType, false);

        usingValidSession();
        usingValidAuthSession();

        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, validBodyWithEmailAndPassword);
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.AUTH_INVALID_CREDENTIALS,
                        auditContextWithAllUserInfo.withTxmaAuditEncoded(
                                Optional.of(ENCODED_DEVICE_DETAILS)),
                        pair("internalSubjectId", INTERNAL_SUBJECT_ID.getValue()),
                        pair("incorrectPasswordCount", 1),
                        pair("attemptNoFailedAt", MAX_ALLOWED_PASSWORD_RETRIES));

        assertThat(result, hasStatus(401));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1008));
        verifyNoInteractions(cloudwatchMetricsService);
        verify(authSessionService, never()).updateSession(any(AuthSessionItem.class));
    }

    @ParameterizedTest
    @CsvSource({"true, true", "false, true", "true, false", "false, false"})
    void shouldIncrementRelevantCountWhenCredentialsAreInvalid(
            boolean isReauthJourney, boolean isReauthEnabled) {
        UserProfile userProfile = generateUserProfile(null);
        when(authenticationService.getUserProfileByEmailMaybe(EMAIL))
                .thenReturn(Optional.of(userProfile));
        usingApplicableUserCredentialsWithLogin(SMS, false);
        when(configurationService.supportReauthSignoutEnabled()).thenReturn(isReauthEnabled);

        usingValidSession();
        usingValidAuthSession();

        var body = isReauthJourney ? validBodyWithReauthJourney : validBodyWithEmailAndPassword;

        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, body);
        handler.handleRequest(event, context);

        if (isReauthJourney && isReauthEnabled) {
            verify(codeStorageService, atLeastOnce())
                    .increaseIncorrectPasswordCountReauthJourney(EMAIL);
        } else {
            verify(codeStorageService, atLeastOnce()).increaseIncorrectPasswordCount(EMAIL);
        }
    }

    @ParameterizedTest
    @EnumSource(MFAMethodType.class)
    void shouldReturn401IfMigratedUserHasInvalidCredentials(MFAMethodType mfaMethodType) {
        String legacySubjectId = new Subject().getValue();
        UserProfile userProfile = generateUserProfile(legacySubjectId);
        when(authenticationService.getUserProfileByEmailMaybe(EMAIL))
                .thenReturn(Optional.of(userProfile));

        UserCredentials applicableUserCredentials = usingApplicableUserCredentials(mfaMethodType);

        when(userMigrationService.processMigratedUser(
                        applicableUserCredentials, CommonTestVariables.PASSWORD))
                .thenReturn(false);
        usingValidSession();
        usingValidAuthSessionWithRequestedCredentialStrength(MEDIUM_LEVEL);

        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, validBodyWithEmailAndPassword);
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(401));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1008));
        verifyNoInteractions(cloudwatchMetricsService);
        verify(authSessionService, never()).updateSession(any(AuthSessionItem.class));
    }

    @Test
    void shouldReturn400IfAnyRequestParametersAreMissing() {
        var bodyWithoutEmail = format("{ \"password\": \"%s\"}", CommonTestVariables.PASSWORD);
        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, bodyWithoutEmail);

        usingValidSession();
        usingValidAuthSession();
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1001));
        verifyNoInteractions(cloudwatchMetricsService);
        verify(authSessionService, never()).updateSession(any(AuthSessionItem.class));
    }

    @Test
    void shouldReturn400IfSessionIdIsInvalid() {
        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, validBodyWithEmailAndPassword);

        when(sessionService.getSessionFromRequestHeaders(event.getHeaders()))
                .thenReturn(Optional.empty());

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1000));
        verifyNoInteractions(cloudwatchMetricsService);
        verify(authSessionService, never()).updateSession(any(AuthSessionItem.class));
    }

    @Test
    void shouldReturn400IfNoAuthSessionPresent() {
        usingInvalidAuthSession();
        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, validBodyWithEmailAndPassword);

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1000));
        verifyNoInteractions(cloudwatchMetricsService);
    }

    @Test
    void shouldReturn400IfUserDoesNotHaveAnAccount() {
        when(authenticationService.getUserProfileByEmailMaybe(EMAIL)).thenReturn(Optional.empty());
        usingValidSession();
        usingValidAuthSession();

        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, validBodyWithEmailAndPassword);
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.AUTH_NO_ACCOUNT_WITH_EMAIL,
                        auditContextWithoutUserInfo.withTxmaAuditEncoded(
                                Optional.of(ENCODED_DEVICE_DETAILS)));

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1010));
        verifyNoInteractions(cloudwatchMetricsService);
        verify(authSessionService, never()).updateSession(any(AuthSessionItem.class));
    }

    @Test
    void shouldReturn500IfFailedToGetMfaMethods() {
        UserProfile userProfile = generateUserProfile(null);
        when(authenticationService.getUserProfileByEmailMaybe(EMAIL))
                .thenReturn(Optional.of(userProfile));
        usingValidSession();
        usingValidAuthSessionWithRequestedCredentialStrength(MEDIUM_LEVEL);
        usingApplicableUserCredentialsWithLogin(SMS, true);
        when(mfaMethodsService.getMfaMethods(EMAIL))
                .thenReturn(
                        Result.failure(
                                UNEXPECTED_ERROR_CREATING_MFA_IDENTIFIER_FOR_NON_MIGRATED_AUTH_APP));

        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, validBodyWithEmailAndPassword);
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(500));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1078));
        verifyNoInteractions(cloudwatchMetricsService);
    }

    @Test
    void shouldReturn500IfFailedToConvertMfaMethodsForResponse() {
        UserProfile userProfile = generateUserProfile(null);
        when(authenticationService.getUserProfileByEmailMaybe(EMAIL))
                .thenReturn(Optional.of(userProfile));
        usingValidSession();
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
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1064));
        verifyNoInteractions(cloudwatchMetricsService);
    }

    @Test
    void termsAndConditionsShouldBeAcceptedIfClientIsSmokeTestClient() throws Json.JsonException {
        when(configurationService.getTermsAndConditionsVersion()).thenReturn("2.0");
        setUpSmokeTestClient();
        UserProfile userProfile = generateUserProfile(null);
        when(authenticationService.getUserProfileByEmailMaybe(EMAIL))
                .thenReturn(Optional.of(userProfile));
        usingValidSession();
        usingApplicableUserCredentialsWithLogin(SMS, true);
        usingValidAuthSessionInSmokeTest();

        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, validBodyWithEmailAndPassword);
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(200));

        LoginResponse response = objectMapper.readValue(result.getBody(), LoginResponse.class);

        assertThat(response.latestTermsAndConditionsAccepted(), equalTo(true));

        verifyNoInteractions(cloudwatchMetricsService);
        verifyInternalCommonSubjectIdentifierSaved();
    }

    @Test
    void shouldDeleteEmailAndPasswordAuthenticationAttemptCountsWhenUserLogsInSuccessfully() {
        // Arrange
        UserProfile userProfile = generateUserProfile(null);
        when(configurationService.isAuthenticationAttemptsServiceEnabled()).thenReturn(true);
        when(authenticationService.getUserProfileByEmailMaybe(EMAIL))
                .thenReturn(Optional.of(userProfile));

        usingValidSession();
        usingValidAuthSession();
        usingApplicableUserCredentialsWithLogin(SMS, true);

        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, validBodyWithEmailAndPassword);

        // Act
        var result = handler.handleRequest(event, context);

        // Assert
        assertThat(result, hasStatus(200));
    }

    @Test
    void shouldUpdateAuthSessionStoreWithExistingAccountState() {
        UserProfile userProfile = generateUserProfile(null);
        when(authenticationService.getUserProfileByEmailMaybe(EMAIL))
                .thenReturn(Optional.of(userProfile));

        usingValidSession();
        usingApplicableUserCredentialsWithLogin(SMS, true);
        usingValidAuthSession();

        var event = apiRequestEventWithHeadersAndBody(VALID_HEADERS, validBodyWithEmailAndPassword);

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(200));
        verifyAuthSessionIsSaved();
    }

    private void usingValidSession() {
        when(sessionService.getSessionFromRequestHeaders(anyMap()))
                .thenReturn(Optional.of(session));
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
                                        .withClientName(CLIENT_NAME)));
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
                                        .withIsSmokeTest(true)));
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

    private ClientRegistry generateClientRegistry() {
        return new ClientRegistry()
                .withClientID(CLIENT_ID.getValue())
                .withClientName(CLIENT_NAME)
                .withSectorIdentifierUri("https://test.com")
                .withSubjectType("public");
    }

    private void setUpSmokeTestClient() {
        when(clientService.getClient(CLIENT_ID.getValue()))
                .thenReturn(
                        Optional.of(
                                new ClientRegistry()
                                        .withSmokeTest(true)
                                        .withClientID(CLIENT_ID.getValue())
                                        .withSectorIdentifierUri("https://test.com")));
    }

    private void verifyInternalCommonSubjectIdentifierSaved() {
        verify(authSessionService, atLeastOnce())
                .updateSession(
                        argThat(t -> t.getInternalCommonSubjectId().equals(expectedCommonSubject)));
    }

    private void verifyAuthSessionIsSaved() {
        verify(authSessionService, times(1))
                .updateSession(
                        argThat(s -> s.getIsNewAccount() == AuthSessionItem.AccountState.EXISTING));
    }
}
