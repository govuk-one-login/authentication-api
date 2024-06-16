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
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent;
import uk.gov.di.authentication.frontendapi.entity.LoginResponse;
import uk.gov.di.authentication.frontendapi.entity.PasswordResetType;
import uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables;
import uk.gov.di.authentication.frontendapi.helpers.FrontendApiPhoneNumberHelper;
import uk.gov.di.authentication.frontendapi.services.UserMigrationService;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.ClientSession;
import uk.gov.di.authentication.shared.entity.CredentialTrustLevel;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.MFAMethod;
import uk.gov.di.authentication.shared.entity.MFAMethodType;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.TermsAndConditions;
import uk.gov.di.authentication.shared.entity.UserCredentials;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.entity.VectorOfTrust;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.helpers.IdGenerator;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.helpers.SaltHelper;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.CommonPasswordsService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.SerializationService;
import uk.gov.di.authentication.shared.services.SessionService;
import uk.gov.di.authentication.sharedtest.logging.CaptureLoggingExtension;

import java.net.URI;
import java.util.Collections;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import static java.lang.String.format;
import static java.util.Objects.nonNull;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.not;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.frontendapi.lambda.StartHandlerTest.CLIENT_SESSION_ID;
import static uk.gov.di.authentication.frontendapi.lambda.StartHandlerTest.CLIENT_SESSION_ID_HEADER;
import static uk.gov.di.authentication.shared.entity.CredentialTrustLevel.LOW_LEVEL;
import static uk.gov.di.authentication.shared.entity.MFAMethodType.SMS;
import static uk.gov.di.authentication.shared.lambda.BaseFrontendHandler.TXMA_AUDIT_ENCODED_HEADER;
import static uk.gov.di.authentication.shared.services.AuditService.MetadataPair.pair;
import static uk.gov.di.authentication.sharedtest.helper.JsonArrayHelper.jsonArrayOf;
import static uk.gov.di.authentication.sharedtest.helper.RequestEventHelper.contextWithSourceIp;
import static uk.gov.di.authentication.sharedtest.logging.LogEventMatcher.withMessageContaining;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class LoginHandlerTest {

    private static final String EMAIL = CommonTestVariables.EMAIL;
    private static final String INTERNAL_SECTOR_URI = "https://test.account.gov.uk";
    public static final String TEST_IP_ADDRESS = "123.123.123.123";
    private final UserCredentials userCredentials =
            new UserCredentials().withEmail(EMAIL).withPassword(CommonTestVariables.PASSWORD);

    private final UserCredentials userCredentialsAuthApp =
            new UserCredentials()
                    .withEmail(EMAIL)
                    .withPassword(CommonTestVariables.PASSWORD)
                    .setMfaMethod(AUTH_APP_MFA_METHOD);
    private static final ClientID CLIENT_ID = new ClientID();
    private static final String CLIENT_NAME = "client-name";
    private static final String PERSISTENT_ID = "some-persistent-id-value";
    private static final Subject INTERNAL_SUBJECT_ID = new Subject();
    private static final byte[] SALT = SaltHelper.generateNewSalt();
    private static final MFAMethod AUTH_APP_MFA_METHOD =
            new MFAMethod()
                    .withMfaMethodType(MFAMethodType.AUTH_APP.getValue())
                    .withMethodVerified(true)
                    .withEnabled(true);
    private static final Json objectMapper = SerializationService.getInstance();
    private static final Session session =
            new Session(IdGenerator.generate()).setEmailAddress(EMAIL);
    public static final String ENCODED_DEVICE_DETAILS =
            "YTtKVSlub1YlOSBTeEI4J3pVLVd7Jjl8VkBfREs2N3clZmN+fnU7fXNbcTJjKyEzN2IuUXIgMGttV058fGhUZ0xhenZUdldEblB8SH18XypwXUhWPXhYXTNQeURW%";
    private static final Map<String, String> VALID_HEADERS =
            Map.ofEntries(
                    Map.entry(PersistentIdHelper.PERSISTENT_ID_HEADER_NAME, PERSISTENT_ID),
                    Map.entry("Session-Id", session.getSessionId()),
                    Map.entry(CLIENT_SESSION_ID_HEADER, CLIENT_SESSION_ID),
                    Map.entry(TXMA_AUDIT_ENCODED_HEADER, ENCODED_DEVICE_DETAILS));
    private LoginHandler handler;
    private final Context context = mock(Context.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final AuthenticationService authenticationService = mock(AuthenticationService.class);
    private final CodeStorageService codeStorageService = mock(CodeStorageService.class);
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
                    session.getSessionId(),
                    expectedCommonSubject,
                    EMAIL,
                    TEST_IP_ADDRESS,
                    CommonTestVariables.UK_MOBILE_NUMBER,
                    PERSISTENT_ID,
                    Optional.empty());

    private final AuditContext auditContextWithoutUserInfo =
            new AuditContext(
                    CLIENT_ID.getValue(),
                    CLIENT_SESSION_ID,
                    session.getSessionId(),
                    AuditService.UNKNOWN,
                    EMAIL,
                    TEST_IP_ADDRESS,
                    AuditService.UNKNOWN,
                    PERSISTENT_ID,
                    Optional.empty());

    @RegisterExtension
    private final CaptureLoggingExtension logging = new CaptureLoggingExtension(LoginHandler.class);

    @AfterEach
    void tearDown() {
        assertThat(logging.events(), not(hasItem(withMessageContaining(session.getSessionId()))));
    }

    @BeforeEach
    void setUp() {
        when(configurationService.getMaxPasswordRetries()).thenReturn(6);
        when(configurationService.getTermsAndConditionsVersion()).thenReturn("1.0");
        when(clientSessionService.getClientSessionFromRequestHeaders(any()))
                .thenReturn(Optional.of(clientSession));
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
                        clientSessionService,
                        clientService,
                        codeStorageService,
                        userMigrationService,
                        auditService,
                        cloudwatchMetricsService,
                        commonPasswordsService);
    }

    @Test
    void shouldReturn200IfLoginIsSuccessfulAndMfaNotRequired() throws Json.JsonException {
        // Arrange
        UserProfile userProfile = generateUserProfile(null);
        when(authenticationService.getUserProfileByEmailMaybe(EMAIL))
                .thenReturn(Optional.of(userProfile));
        when(clientSession.getAuthRequestParams())
                .thenReturn(generateAuthRequest(LOW_LEVEL).toParameters());
        var vot =
                VectorOfTrust.parseFromAuthRequestAttribute(
                        Collections.singletonList(jsonArrayOf("P0.Cl")));
        when(clientSession.getEffectiveVectorOfTrust()).thenReturn(vot);

        usingValidSession();
        usingApplicableUserCredentialsWithLogin(SMS, true);

        var event = eventWithHeadersAndBody(VALID_HEADERS, validBodyWithEmailAndPassword);

        AuditContext expectedAuditContext =
                new AuditContext(
                        CLIENT_ID.getValue(),
                        CLIENT_SESSION_ID,
                        session.getSessionId(),
                        expectedCommonSubject,
                        EMAIL,
                        TEST_IP_ADDRESS,
                        CommonTestVariables.UK_MOBILE_NUMBER,
                        PERSISTENT_ID,
                        Optional.of(ENCODED_DEVICE_DETAILS));

        // Act
        var result = handler.handleRequest(event, context);

        // Assert
        assertThat(result, hasStatus(200));

        LoginResponse response = objectMapper.readValue(result.getBody(), LoginResponse.class);

        assertThat(
                response.getRedactedPhoneNumber(),
                equalTo(
                        FrontendApiPhoneNumberHelper.redactPhoneNumber(
                                CommonTestVariables.UK_MOBILE_NUMBER)));
        assertThat(response.getLatestTermsAndConditionsAccepted(), equalTo(true));

        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.LOG_IN_SUCCESS,
                        expectedAuditContext,
                        pair("internalSubjectId", INTERNAL_SUBJECT_ID.getValue()));

        verify(cloudwatchMetricsService)
                .incrementAuthenticationSuccess(
                        Session.AccountState.EXISTING,
                        CLIENT_ID.getValue(),
                        CLIENT_NAME,
                        "P0",
                        false,
                        false);

        verifySessionIsSaved();
    }

    @Test
    void checkAuditEventStillEmittedWhenTICFHeaderNotProvided() throws Json.JsonException {
        UserProfile userProfile = generateUserProfile(null);
        when(authenticationService.getUserProfileByEmailMaybe(EMAIL))
                .thenReturn(Optional.of(userProfile));
        when(clientSession.getAuthRequestParams())
                .thenReturn(generateAuthRequest(LOW_LEVEL).toParameters());
        var vot =
                VectorOfTrust.parseFromAuthRequestAttribute(
                        Collections.singletonList(jsonArrayOf("P0.Cl")));
        when(clientSession.getEffectiveVectorOfTrust()).thenReturn(vot);

        usingValidSession();
        usingApplicableUserCredentialsWithLogin(SMS, true);

        var headersWithoutTICFHeader =
                VALID_HEADERS.entrySet().stream()
                        .filter(entry -> !entry.getKey().equals(TXMA_AUDIT_ENCODED_HEADER))
                        .collect(
                                Collectors.toUnmodifiableMap(
                                        Map.Entry::getKey, Map.Entry::getValue));

        var event =
                eventWithHeadersAndBody(headersWithoutTICFHeader, validBodyWithEmailAndPassword);

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(200));

        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.LOG_IN_SUCCESS,
                        auditContextWithAllUserInfo,
                        pair("internalSubjectId", INTERNAL_SUBJECT_ID.getValue()));
    }

    @ParameterizedTest
    @EnumSource(MFAMethodType.class)
    void shouldReturn200IfLoginIsSuccessfulAndMfaIsRequired(MFAMethodType mfaMethodType) {
        UserProfile userProfile = generateUserProfile(null);
        when(authenticationService.getUserProfileByEmailMaybe(EMAIL))
                .thenReturn(Optional.of(userProfile));
        when(clientSession.getAuthRequestParams()).thenReturn(generateAuthRequest().toParameters());
        usingValidSession();
        usingApplicableUserCredentialsWithLogin(mfaMethodType, true);
        usingDefaultVectorOfTrust();

        var event = eventWithHeadersAndBody(VALID_HEADERS, validBodyWithEmailAndPassword);
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(200));

        verifyNoInteractions(cloudwatchMetricsService);

        verifySessionIsSaved();
    }

    @ParameterizedTest
    @EnumSource(MFAMethodType.class)
    void shouldReturn200IfLoginIsSuccessfulAndTermsAndConditionsNotAccepted(
            MFAMethodType mfaMethodType) throws Json.JsonException {
        when(configurationService.getTermsAndConditionsVersion()).thenReturn("2.0");
        UserProfile userProfile = generateUserProfile(null);
        when(authenticationService.getUserProfileByEmailMaybe(EMAIL))
                .thenReturn(Optional.of(userProfile));
        when(clientSession.getAuthRequestParams()).thenReturn(generateAuthRequest().toParameters());
        usingValidSession();
        usingApplicableUserCredentialsWithLogin(mfaMethodType, true);
        usingDefaultVectorOfTrust();

        var event = eventWithHeadersAndBody(VALID_HEADERS, validBodyWithEmailAndPassword);
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(200));

        LoginResponse response = objectMapper.readValue(result.getBody(), LoginResponse.class);

        assertThat(response.getLatestTermsAndConditionsAccepted(), equalTo(false));

        verifyNoInteractions(cloudwatchMetricsService);
        verifySessionIsSaved();
    }

    @Test
    void shouldReturn200WithCorrectMfaMethodVerifiedStatus() throws Json.JsonException {
        var userProfile = generateUserProfile(null);
        var userCredentials =
                new UserCredentials()
                        .withEmail(EMAIL)
                        .withPassword(CommonTestVariables.PASSWORD)
                        .setMfaMethod(
                                new MFAMethod()
                                        .withMfaMethodType(MFAMethodType.AUTH_APP.getValue())
                                        .withMethodVerified(false)
                                        .withEnabled(true));
        when(authenticationService.login(userCredentials, CommonTestVariables.PASSWORD))
                .thenReturn(true);
        when(authenticationService.getUserProfileByEmailMaybe(EMAIL))
                .thenReturn(Optional.of(userProfile));
        when(authenticationService.getUserCredentialsFromEmail(EMAIL)).thenReturn(userCredentials);
        when(clientSession.getAuthRequestParams()).thenReturn(generateAuthRequest().toParameters());
        usingValidSession();

        usingDefaultVectorOfTrust();

        var event = eventWithHeadersAndBody(VALID_HEADERS, validBodyWithEmailAndPassword);
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(200));

        var response = objectMapper.readValue(result.getBody(), LoginResponse.class);
        assertThat(response.getMfaMethodType(), equalTo(SMS));
        assertThat(response.isMfaMethodVerified(), equalTo(true));

        verifyNoInteractions(cloudwatchMetricsService);

        verifySessionIsSaved();
    }

    @ParameterizedTest
    @EnumSource(MFAMethodType.class)
    void shouldReturn200IfLoginIsSuccessfulButPasswordWasCommonPassword(MFAMethodType mfaMethodType)
            throws Json.JsonException {
        when(commonPasswordsService.isCommonPassword(anyString())).thenReturn(true);
        UserProfile userProfile = generateUserProfile(null);
        when(authenticationService.getUserProfileByEmailMaybe(EMAIL))
                .thenReturn(Optional.of(userProfile));
        when(clientSession.getAuthRequestParams()).thenReturn(generateAuthRequest().toParameters());
        usingValidSession();
        usingApplicableUserCredentialsWithLogin(mfaMethodType, true);
        usingDefaultVectorOfTrust();

        var event = eventWithHeadersAndBody(VALID_HEADERS, validBodyWithEmailAndPassword);
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);
        assertThat(result, hasStatus(200));

        LoginResponse response = objectMapper.readValue(result.getBody(), LoginResponse.class);
        assertThat(response.isPasswordChangeRequired(), equalTo(true));
        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.LOG_IN_SUCCESS,
                        auditContextWithAllUserInfo.withTxmaAuditEncoded(
                                Optional.of(ENCODED_DEVICE_DETAILS)),
                        pair("internalSubjectId", INTERNAL_SUBJECT_ID.getValue()),
                        pair("passwordResetType", PasswordResetType.FORCED_WEAK_PASSWORD));
        verifyNoInteractions(cloudwatchMetricsService);
        verifySessionIsSaved();
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
        when(clientSession.getAuthRequestParams()).thenReturn(generateAuthRequest().toParameters());
        usingValidSession();
        usingDefaultVectorOfTrust();

        var event = eventWithHeadersAndBody(VALID_HEADERS, validBodyWithEmailAndPassword);
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(200));

        LoginResponse response = objectMapper.readValue(result.getBody(), LoginResponse.class);
        assertThat(response.getLatestTermsAndConditionsAccepted(), equalTo(true));

        verifyNoInteractions(cloudwatchMetricsService);
        verifySessionIsSaved();
    }

    @ParameterizedTest
    @EnumSource(MFAMethodType.class)
    void shouldChangeStateToAccountTemporarilyLockedAfterAttemptsReachMaxRetries(
            MFAMethodType mfaMethodType) {
        UserProfile userProfile = generateUserProfile(null);
        when(authenticationService.getUserProfileByEmailMaybe(EMAIL))
                .thenReturn(Optional.of(userProfile));
        when(clientSession.getAuthRequestParams()).thenReturn(generateAuthRequest().toParameters());

        var maxRetriesAllowed = configurationService.getMaxPasswordRetries();
        when(codeStorageService.getIncorrectPasswordCount(EMAIL)).thenReturn(maxRetriesAllowed - 1);
        usingValidSession();
        usingApplicableUserCredentialsWithLogin(mfaMethodType, false);
        usingDefaultVectorOfTrust();

        var event = eventWithHeadersAndBody(VALID_HEADERS, validBodyWithEmailAndPassword);
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));

        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1028));
        verifyNoInteractions(cloudwatchMetricsService);
        verify(sessionService, never()).save(any());

        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.ACCOUNT_TEMPORARILY_LOCKED,
                        auditContextWithAllUserInfo.withTxmaAuditEncoded(
                                Optional.of(ENCODED_DEVICE_DETAILS)),
                        pair("internalSubjectId", userProfile.getSubjectID()),
                        pair("attemptNoFailedAt", maxRetriesAllowed),
                        pair("number_of_attempts_user_allowed_to_login", maxRetriesAllowed));
    }

    @ParameterizedTest
    @EnumSource(MFAMethodType.class)
    void shouldChangeStateToAccountTemporarilyLockedAfterAttemptsReachMaxRetriesForReauthJourney(
            MFAMethodType mfaMethodType) {
        UserProfile userProfile = generateUserProfile(null);
        when(authenticationService.getUserProfileByEmailMaybe(EMAIL))
                .thenReturn(Optional.of(userProfile));
        when(clientSession.getAuthRequestParams()).thenReturn(generateAuthRequest().toParameters());
        var maxRetriesAllowed = configurationService.getMaxPasswordRetries();
        when(codeStorageService.getIncorrectPasswordCountReauthJourney(EMAIL))
                .thenReturn(maxRetriesAllowed - 1);
        usingValidSession();
        usingApplicableUserCredentialsWithLogin(mfaMethodType, false);
        usingDefaultVectorOfTrust();

        var event = eventWithHeadersAndBody(VALID_HEADERS, validBodyWithReauthJourney);
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));

        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1028));

        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.INVALID_CREDENTIALS,
                        auditContextWithAllUserInfo.withTxmaAuditEncoded(
                                Optional.of(ENCODED_DEVICE_DETAILS)),
                        pair("internalSubjectId", userProfile.getSubjectID()),
                        pair("incorrectPasswordCount", maxRetriesAllowed),
                        pair("attemptNoFailedAt", maxRetriesAllowed));

        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.ACCOUNT_TEMPORARILY_LOCKED,
                        auditContextWithAllUserInfo.withTxmaAuditEncoded(
                                Optional.of(ENCODED_DEVICE_DETAILS)),
                        pair("internalSubjectId", userProfile.getSubjectID()),
                        pair("attemptNoFailedAt", maxRetriesAllowed),
                        pair("number_of_attempts_user_allowed_to_login", maxRetriesAllowed));
        verifyNoInteractions(cloudwatchMetricsService);
        verify(sessionService, never()).save(any());
    }

    @ParameterizedTest
    @EnumSource(MFAMethodType.class)
    void shouldKeepUserLockedWhenTheyEnterSuccessfulLoginRequestInNewSession(
            MFAMethodType mfaMethodType) {
        UserProfile userProfile = generateUserProfile(null);
        when(authenticationService.getUserProfileByEmailMaybe(EMAIL))
                .thenReturn(Optional.of(userProfile));
        when(clientSession.getAuthRequestParams()).thenReturn(generateAuthRequest().toParameters());
        when(codeStorageService.getIncorrectPasswordCount(EMAIL)).thenReturn(6);
        usingValidSession();
        usingApplicableUserCredentialsWithLogin(mfaMethodType, true);
        usingDefaultVectorOfTrust();

        var event = eventWithHeadersAndBody(VALID_HEADERS, validBodyWithEmailAndPassword);
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1028));

        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.ACCOUNT_TEMPORARILY_LOCKED,
                        auditContextWithAllUserInfo.withTxmaAuditEncoded(
                                Optional.of(ENCODED_DEVICE_DETAILS)),
                        pair("internalSubjectId", INTERNAL_SUBJECT_ID.getValue()),
                        pair("attemptNoFailedAt", configurationService.getMaxPasswordRetries()),
                        pair(
                                "number_of_attempts_user_allowed_to_login",
                                configurationService.getMaxPasswordRetries()));
        verifyNoInteractions(cloudwatchMetricsService);
        verify(sessionService, never()).save(any());
    }

    @ParameterizedTest
    @EnumSource(MFAMethodType.class)
    void shouldRemoveIncorrectPasswordCountRemovesUponSuccessfulLogin(MFAMethodType mfaMethodType) {
        UserProfile userProfile = generateUserProfile(null);
        when(authenticationService.getUserProfileByEmailMaybe(EMAIL))
                .thenReturn(Optional.of(userProfile));
        UserCredentials applicableUserCredentials = usingApplicableUserCredentials(mfaMethodType);
        when(codeStorageService.getIncorrectPasswordCount(EMAIL)).thenReturn(4);
        usingValidSession();
        usingDefaultVectorOfTrust();

        var event = eventWithHeadersAndBody(VALID_HEADERS, validBodyWithEmailAndPassword);
        handler.handleRequest(event, context);

        when(authenticationService.login(applicableUserCredentials, CommonTestVariables.PASSWORD))
                .thenReturn(true);
        when(clientSession.getAuthRequestParams()).thenReturn(generateAuthRequest().toParameters());

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(200));
        verifyNoInteractions(cloudwatchMetricsService);
        verifySessionIsSaved();
    }

    @ParameterizedTest
    @EnumSource(MFAMethodType.class)
    void shouldReturn401IfUserHasInvalidCredentials(MFAMethodType mfaMethodType) {
        UserProfile userProfile = generateUserProfile(null);
        when(authenticationService.getUserProfileByEmailMaybe(EMAIL))
                .thenReturn(Optional.of(userProfile));
        when(clientSession.getAuthRequestParams()).thenReturn(generateAuthRequest().toParameters());
        usingApplicableUserCredentialsWithLogin(mfaMethodType, false);

        usingValidSession();
        usingDefaultVectorOfTrust();

        var event = eventWithHeadersAndBody(VALID_HEADERS, validBodyWithEmailAndPassword);
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.INVALID_CREDENTIALS,
                        auditContextWithAllUserInfo.withTxmaAuditEncoded(
                                Optional.of(ENCODED_DEVICE_DETAILS)),
                        pair("internalSubjectId", INTERNAL_SUBJECT_ID.getValue()),
                        pair("incorrectPasswordCount", 1),
                        pair("attemptNoFailedAt", 6));

        assertThat(result, hasStatus(401));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1008));
        verifyNoInteractions(cloudwatchMetricsService);
        verify(sessionService, never()).save(any());
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldIncrementRelevantCountWhenCredentialsAreInvalid(Boolean isReauthJourney) {
        UserProfile userProfile = generateUserProfile(null);
        when(authenticationService.getUserProfileByEmailMaybe(EMAIL))
                .thenReturn(Optional.of(userProfile));
        usingApplicableUserCredentialsWithLogin(SMS, false);

        usingValidSession();
        usingDefaultVectorOfTrust();

        var body = isReauthJourney ? validBodyWithReauthJourney : validBodyWithEmailAndPassword;

        var event = eventWithHeadersAndBody(VALID_HEADERS, body);
        handler.handleRequest(event, context);

        if (isReauthJourney) {
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
        usingDefaultVectorOfTrust();

        var event = eventWithHeadersAndBody(VALID_HEADERS, validBodyWithEmailAndPassword);
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(401));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1008));
        verifyNoInteractions(cloudwatchMetricsService);
        verify(sessionService, never()).save(any());
    }

    @Test
    void shouldReturn400IfAnyRequestParametersAreMissing() {
        var bodyWithoutEmail = format("{ \"password\": \"%s\"}", CommonTestVariables.PASSWORD);
        var event = eventWithHeadersAndBody(VALID_HEADERS, bodyWithoutEmail);

        usingValidSession();
        usingDefaultVectorOfTrust();
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1001));
        verifyNoInteractions(cloudwatchMetricsService);
        verify(sessionService, never()).save(any());
    }

    @Test
    void shouldReturn400IfSessionIdIsInvalid() {
        var event = eventWithHeadersAndBody(VALID_HEADERS, validBodyWithEmailAndPassword);

        when(sessionService.getSessionFromRequestHeaders(event.getHeaders()))
                .thenReturn(Optional.empty());

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1000));
        verifyNoInteractions(cloudwatchMetricsService);
        verify(sessionService, never()).save(any());
    }

    @Test
    void shouldReturn400IfUserDoesNotHaveAnAccount() {
        when(authenticationService.getUserProfileByEmailMaybe(EMAIL)).thenReturn(Optional.empty());
        when(clientSession.getAuthRequestParams()).thenReturn(generateAuthRequest().toParameters());
        usingValidSession();
        usingDefaultVectorOfTrust();

        var event = eventWithHeadersAndBody(VALID_HEADERS, validBodyWithEmailAndPassword);
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.NO_ACCOUNT_WITH_EMAIL,
                        auditContextWithoutUserInfo.withTxmaAuditEncoded(
                                Optional.of(ENCODED_DEVICE_DETAILS)));

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1010));
        verifyNoInteractions(cloudwatchMetricsService);
        verify(sessionService, never()).save(any(Session.class));
    }

    @Test
    void termsAndConditionsShouldBeAcceptedIfClientIsSmokeTestClient() throws Json.JsonException {
        when(configurationService.getTermsAndConditionsVersion()).thenReturn("2.0");
        setUpSmokeTestClient();
        UserProfile userProfile = generateUserProfile(null);
        when(authenticationService.getUserProfileByEmailMaybe(EMAIL))
                .thenReturn(Optional.of(userProfile));
        when(clientSession.getAuthRequestParams()).thenReturn(generateAuthRequest().toParameters());
        usingValidSession();
        usingApplicableUserCredentialsWithLogin(SMS, true);
        usingDefaultVectorOfTrust();

        var event = eventWithHeadersAndBody(VALID_HEADERS, validBodyWithEmailAndPassword);
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(200));

        LoginResponse response = objectMapper.readValue(result.getBody(), LoginResponse.class);

        assertThat(response.getLatestTermsAndConditionsAccepted(), equalTo(true));

        verifyNoInteractions(cloudwatchMetricsService);
        verifySessionIsSaved();
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

    private void usingDefaultVectorOfTrust() {
        VectorOfTrust vectorOfTrust =
                VectorOfTrust.parseFromAuthRequestAttribute(
                        Collections.singletonList(jsonArrayOf("Cl.Cm")));
        when(clientSession.getEffectiveVectorOfTrust()).thenReturn(vectorOfTrust);
    }

    private void setUpSmokeTestClient() {
        when(clientService.getClient(CLIENT_ID.getValue()))
                .thenReturn(
                        Optional.of(
                                new ClientRegistry()
                                        .withSmokeTest(true)
                                        .withClientID(CLIENT_ID.getValue())));
    }

    private APIGatewayProxyRequestEvent eventWithHeadersAndBody(
            Map<String, String> headers, String body) {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setRequestContext(contextWithSourceIp(TEST_IP_ADDRESS));
        event.setHeaders(headers);
        event.setBody(body);
        return event;
    }

    private void verifySessionIsSaved() {
        verify(sessionService, atLeastOnce())
                .save(
                        argThat(
                                t ->
                                        t.getInternalCommonSubjectIdentifier()
                                                        .equals(expectedCommonSubject)
                                                && t.isNewAccount()
                                                        == Session.AccountState.EXISTING));
    }
}
