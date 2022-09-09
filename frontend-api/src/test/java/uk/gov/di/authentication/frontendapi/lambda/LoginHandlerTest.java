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
import uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent;
import uk.gov.di.authentication.frontendapi.entity.LoginResponse;
import uk.gov.di.authentication.frontendapi.helpers.RedactPhoneNumberHelper;
import uk.gov.di.authentication.frontendapi.services.UserMigrationService;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.ClientSession;
import uk.gov.di.authentication.shared.entity.CredentialTrustLevel;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.MFAMethod;
import uk.gov.di.authentication.shared.entity.MFAMethodType;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.TermsAndConditions;
import uk.gov.di.authentication.shared.entity.UserCredentials;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.entity.VectorOfTrust;
import uk.gov.di.authentication.shared.helpers.IdGenerator;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
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
import uk.gov.di.authentication.sharedtest.logging.CaptureLoggingExtension;

import java.net.URI;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static java.lang.String.format;
import static java.util.Objects.nonNull;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.not;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.frontendapi.lambda.StartHandlerTest.CLIENT_SESSION_ID;
import static uk.gov.di.authentication.frontendapi.lambda.StartHandlerTest.CLIENT_SESSION_ID_HEADER;
import static uk.gov.di.authentication.shared.entity.CredentialTrustLevel.LOW_LEVEL;
import static uk.gov.di.authentication.shared.entity.MFAMethodType.SMS;
import static uk.gov.di.authentication.sharedtest.helper.JsonArrayHelper.jsonArrayOf;
import static uk.gov.di.authentication.sharedtest.helper.RequestEventHelper.contextWithSourceIp;
import static uk.gov.di.authentication.sharedtest.logging.LogEventMatcher.withMessageContaining;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class LoginHandlerTest {

    private static final String EMAIL = "joe.bloggs@test.com";
    private static final String PASSWORD = "computer-1";
    private final UserCredentials userCredentials =
            new UserCredentials().setEmail(EMAIL).setPassword(PASSWORD);

    private final UserCredentials userCredentialsAuthApp =
            new UserCredentials()
                    .setEmail(EMAIL)
                    .setPassword(PASSWORD)
                    .setMfaMethod(AUTH_APP_MFA_METHOD);
    private static final String PHONE_NUMBER = "01234567890";
    private static final ClientID CLIENT_ID = new ClientID();
    private static final MFAMethod AUTH_APP_MFA_METHOD =
            new MFAMethod()
                    .setMfaMethodType(MFAMethodType.AUTH_APP.getValue())
                    .setMethodVerified(true)
                    .setEnabled(true);
    private static final Json objectMapper = SerializationService.getInstance();
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

    private final Session session = new Session(IdGenerator.generate()).setEmailAddress(EMAIL);

    @RegisterExtension
    private final CaptureLoggingExtension logging = new CaptureLoggingExtension(LoginHandler.class);

    @AfterEach
    void tearDown() {
        assertThat(logging.events(), not(hasItem(withMessageContaining(session.getSessionId()))));
    }

    @BeforeEach
    void setUp() {
        when(configurationService.getMaxPasswordRetries()).thenReturn(5);
        when(clientSessionService.getClientSessionFromRequestHeaders(any()))
                .thenReturn(Optional.of(clientSession));
        when(context.getAwsRequestId()).thenReturn("aws-session-id");

        when(clientService.getClient(CLIENT_ID.getValue()))
                .thenReturn(Optional.of(generateClientRegistry()));

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
                        cloudwatchMetricsService);
    }

    @Test
    void shouldReturn200IfLoginIsSuccessfulAndMfaNotRequired() throws Json.JsonException {
        when(configurationService.getTermsAndConditionsVersion()).thenReturn("1.0");
        String persistentId = "some-persistent-id-value";
        Map<String, String> headers = new HashMap<>();
        headers.put(PersistentIdHelper.PERSISTENT_ID_HEADER_NAME, persistentId);
        headers.put("Session-Id", session.getSessionId());
        headers.put(CLIENT_SESSION_ID_HEADER, CLIENT_SESSION_ID);
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

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setRequestContext(contextWithSourceIp("123.123.123.123"));
        event.setHeaders(headers);
        event.setBody(
                format(
                        "{ \"password\": \"%s\", \"email\": \"%s\" }",
                        PASSWORD, EMAIL.toUpperCase()));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(200));

        LoginResponse response = objectMapper.readValue(result.getBody(), LoginResponse.class);
        assertThat(
                response.getRedactedPhoneNumber(),
                equalTo(RedactPhoneNumberHelper.redactPhoneNumber(PHONE_NUMBER)));
        assertThat(response.getLatestTermsAndConditionsAccepted(), equalTo(true));
        verify(authenticationService).getUserProfileByEmailMaybe(EMAIL);

        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.LOG_IN_SUCCESS,
                        CLIENT_SESSION_ID,
                        session.getSessionId(),
                        CLIENT_ID.getValue(),
                        userProfile.getSubjectID(),
                        userProfile.getEmail(),
                        "123.123.123.123",
                        userProfile.getPhoneNumber(),
                        persistentId);
        verify(cloudwatchMetricsService)
                .incrementAuthenticationSuccess(
                        Session.AccountState.EXISTING, CLIENT_ID.getValue(), "P0", false, false);
    }

    @ParameterizedTest
    @EnumSource(MFAMethodType.class)
    void shouldReturn200IfLoginIsSuccessful(MFAMethodType mfaMethodType) throws Json.JsonException {
        when(configurationService.getTermsAndConditionsVersion()).thenReturn("1.0");
        String persistentId = "some-persistent-id-value";
        Map<String, String> headers = new HashMap<>();
        headers.put(PersistentIdHelper.PERSISTENT_ID_HEADER_NAME, persistentId);
        headers.put("Session-Id", session.getSessionId());
        headers.put(CLIENT_SESSION_ID_HEADER, CLIENT_SESSION_ID);
        UserProfile userProfile = generateUserProfile(null);
        when(authenticationService.getUserProfileByEmailMaybe(EMAIL))
                .thenReturn(Optional.of(userProfile));
        when(clientSession.getAuthRequestParams()).thenReturn(generateAuthRequest().toParameters());
        usingValidSession();
        usingApplicableUserCredentialsWithLogin(mfaMethodType, true);
        usingDefaultVectorOfTrust();

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setRequestContext(contextWithSourceIp("123.123.123.123"));
        event.setHeaders(headers);
        event.setBody(
                format(
                        "{ \"password\": \"%s\", \"email\": \"%s\" }",
                        PASSWORD, EMAIL.toUpperCase()));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(200));

        LoginResponse response = objectMapper.readValue(result.getBody(), LoginResponse.class);
        assertThat(
                response.getRedactedPhoneNumber(),
                equalTo(RedactPhoneNumberHelper.redactPhoneNumber(PHONE_NUMBER)));
        assertThat(response.getLatestTermsAndConditionsAccepted(), equalTo(true));
        verify(authenticationService).getUserProfileByEmailMaybe(EMAIL);

        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.LOG_IN_SUCCESS,
                        CLIENT_SESSION_ID,
                        session.getSessionId(),
                        CLIENT_ID.getValue(),
                        userProfile.getSubjectID(),
                        userProfile.getEmail(),
                        "123.123.123.123",
                        userProfile.getPhoneNumber(),
                        persistentId);
        verify(cloudwatchMetricsService, never())
                .incrementAuthenticationSuccess(any(), any(), any(), anyBoolean(), anyBoolean());
    }

    @ParameterizedTest
    @EnumSource(MFAMethodType.class)
    void shouldReturn200IfLoginIsSuccessfulAndTermsAndConditionsNotAccepted(
            MFAMethodType mfaMethodType) throws Json.JsonException {
        when(configurationService.getTermsAndConditionsVersion()).thenReturn("2.0");
        String persistentId = "some-persistent-id-value";
        Map<String, String> headers = new HashMap<>();
        headers.put(PersistentIdHelper.PERSISTENT_ID_HEADER_NAME, persistentId);
        headers.put("Session-Id", session.getSessionId());
        headers.put(CLIENT_SESSION_ID_HEADER, CLIENT_SESSION_ID);
        UserProfile userProfile = generateUserProfile(null);
        when(authenticationService.getUserProfileByEmailMaybe(EMAIL))
                .thenReturn(Optional.of(userProfile));
        when(clientSession.getAuthRequestParams()).thenReturn(generateAuthRequest().toParameters());
        usingValidSession();
        usingApplicableUserCredentialsWithLogin(mfaMethodType, true);
        usingDefaultVectorOfTrust();

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setRequestContext(contextWithSourceIp("123.123.123.123"));
        event.setHeaders(headers);
        event.setBody(
                format(
                        "{ \"password\": \"%s\", \"email\": \"%s\" }",
                        PASSWORD, EMAIL.toUpperCase()));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(200));

        LoginResponse response = objectMapper.readValue(result.getBody(), LoginResponse.class);
        assertThat(
                response.getRedactedPhoneNumber(),
                equalTo(RedactPhoneNumberHelper.redactPhoneNumber(PHONE_NUMBER)));
        assertThat(response.getLatestTermsAndConditionsAccepted(), equalTo(false));
        verify(authenticationService).getUserProfileByEmailMaybe(EMAIL);

        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.LOG_IN_SUCCESS,
                        CLIENT_SESSION_ID,
                        session.getSessionId(),
                        CLIENT_ID.getValue(),
                        userProfile.getSubjectID(),
                        userProfile.getEmail(),
                        "123.123.123.123",
                        userProfile.getPhoneNumber(),
                        persistentId);

        verify(sessionService)
                .save(argThat(session -> session.isNewAccount() == Session.AccountState.EXISTING));
        verify(cloudwatchMetricsService, never())
                .incrementAuthenticationSuccess(any(), any(), any(), anyBoolean(), anyBoolean());
    }

    @ParameterizedTest
    @EnumSource(MFAMethodType.class)
    void shouldReturn200IfMigratedUserHasBeenProcessesSuccessfully(MFAMethodType mfaMethodType)
            throws Json.JsonException {
        when(configurationService.getTermsAndConditionsVersion()).thenReturn("1.0");
        String legacySubjectId = new Subject().getValue();
        UserProfile userProfile = generateUserProfile(legacySubjectId);
        when(authenticationService.getUserProfileByEmailMaybe(EMAIL))
                .thenReturn(Optional.of(userProfile));
        UserCredentials applicableUserCredentials =
                usingApplicableUserCredentialsWithLogin(mfaMethodType, false);
        applicableUserCredentials.setPassword(null);
        when(userMigrationService.processMigratedUser(applicableUserCredentials, PASSWORD))
                .thenReturn(true);
        when(clientSession.getAuthRequestParams()).thenReturn(generateAuthRequest().toParameters());
        usingValidSession();
        usingDefaultVectorOfTrust();

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("Session-Id", session.getSessionId()));
        event.setBody(format("{ \"password\": \"%s\", \"email\": \"%s\" }", PASSWORD, EMAIL));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(200));

        LoginResponse response = objectMapper.readValue(result.getBody(), LoginResponse.class);
        assertThat(response.getLatestTermsAndConditionsAccepted(), equalTo(true));
        assertThat(
                response.getRedactedPhoneNumber(),
                equalTo(RedactPhoneNumberHelper.redactPhoneNumber(PHONE_NUMBER)));

        verify(sessionService)
                .save(argThat(session -> session.isNewAccount() == Session.AccountState.EXISTING));
    }

    @ParameterizedTest
    @EnumSource(MFAMethodType.class)
    void shouldReturn200IfPasswordIsEnteredAgain(MFAMethodType mfaMethodType)
            throws Json.JsonException {
        UserProfile userProfile = generateUserProfile(null);
        when(authenticationService.getUserProfileByEmailMaybe(EMAIL))
                .thenReturn(Optional.of(userProfile));
        when(clientSession.getAuthRequestParams()).thenReturn(generateAuthRequest().toParameters());

        usingValidSession();
        usingApplicableUserCredentialsWithLogin(mfaMethodType, true);
        usingDefaultVectorOfTrust();

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("Session-Id", session.getSessionId()));
        event.setBody(format("{ \"password\": \"%s\", \"email\": \"%s\" }", PASSWORD, EMAIL));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(200));

        LoginResponse response = objectMapper.readValue(result.getBody(), LoginResponse.class);
        assertThat(
                response.getRedactedPhoneNumber(),
                equalTo(RedactPhoneNumberHelper.redactPhoneNumber(PHONE_NUMBER)));

        verify(sessionService)
                .save(argThat(session -> session.isNewAccount() == Session.AccountState.EXISTING));
    }

    @ParameterizedTest
    @EnumSource(MFAMethodType.class)
    void shouldChangeStateToAccountTemporarilyLockedAfter5UnsuccessfulAttempts(
            MFAMethodType mfaMethodType) {
        UserProfile userProfile = generateUserProfile(null);
        when(authenticationService.getUserProfileByEmailMaybe(EMAIL))
                .thenReturn(Optional.of(userProfile));
        when(codeStorageService.getIncorrectPasswordCount(EMAIL)).thenReturn(5);
        usingValidSession();
        usingApplicableUserCredentialsWithLogin(mfaMethodType, false);
        usingDefaultVectorOfTrust();

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("Session-Id", session.getSessionId()));
        event.setBody(format("{ \"password\": \"%s\", \"email\": \"%s\" }", PASSWORD, EMAIL));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));

        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1028));
    }

    @ParameterizedTest
    @EnumSource(MFAMethodType.class)
    void shouldKeepUserLockedWhenTheyEnterSuccessfulLoginRequestInNewSession(
            MFAMethodType mfaMethodType) {
        UserProfile userProfile = generateUserProfile(null);
        when(authenticationService.getUserProfileByEmailMaybe(EMAIL))
                .thenReturn(Optional.of(userProfile));
        when(codeStorageService.getIncorrectPasswordCount(EMAIL)).thenReturn(5);
        usingValidSession();
        usingApplicableUserCredentialsWithLogin(mfaMethodType, true);
        usingDefaultVectorOfTrust();

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setRequestContext(contextWithSourceIp("123.123.123.123"));
        event.setHeaders(
                Map.of(
                        "Session-Id",
                        session.getSessionId(),
                        CLIENT_SESSION_ID_HEADER,
                        CLIENT_SESSION_ID));
        event.setBody(format("{ \"password\": \"%s\", \"email\": \"%s\" }", PASSWORD, EMAIL));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1028));

        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.ACCOUNT_TEMPORARILY_LOCKED,
                        CLIENT_SESSION_ID,
                        session.getSessionId(),
                        "",
                        userProfile.getSubjectID(),
                        userProfile.getEmail(),
                        "123.123.123.123",
                        userProfile.getPhoneNumber(),
                        PersistentIdHelper.PERSISTENT_ID_UNKNOWN_VALUE);
    }

    @ParameterizedTest
    @EnumSource(MFAMethodType.class)
    void shouldRemoveIncorrectPasswordCountRemovesUponSuccessfulLogin(MFAMethodType mfaMethodType)
            throws Json.JsonException {
        UserProfile userProfile = generateUserProfile(null);
        when(authenticationService.getUserProfileByEmailMaybe(EMAIL))
                .thenReturn(Optional.of(userProfile));
        UserCredentials applicableUserCredentials = usingApplicableUserCredentials(mfaMethodType);
        when(codeStorageService.getIncorrectPasswordCount(EMAIL)).thenReturn(4);
        usingValidSession();
        usingDefaultVectorOfTrust();

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("Session-Id", session.getSessionId()));
        event.setBody(format("{ \"password\": \"%s\", \"email\": \"%s\" }", PASSWORD, EMAIL));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        when(authenticationService.login(applicableUserCredentials, PASSWORD)).thenReturn(true);
        when(clientSession.getAuthRequestParams()).thenReturn(generateAuthRequest().toParameters());

        APIGatewayProxyResponseEvent result2 = handler.handleRequest(event, context);

        assertThat(result2, hasStatus(200));

        LoginResponse response = objectMapper.readValue(result2.getBody(), LoginResponse.class);
    }

    @ParameterizedTest
    @EnumSource(MFAMethodType.class)
    void shouldReturn401IfUserHasInvalidCredentials(MFAMethodType mfaMethodType) {
        UserProfile userProfile = generateUserProfile(null);
        when(authenticationService.getUserProfileByEmailMaybe(EMAIL))
                .thenReturn(Optional.of(userProfile));
        usingApplicableUserCredentialsWithLogin(mfaMethodType, false);

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setRequestContext(contextWithSourceIp("123.123.123.123"));
        event.setHeaders(
                Map.of(
                        "Session-Id",
                        session.getSessionId(),
                        CLIENT_SESSION_ID_HEADER,
                        CLIENT_SESSION_ID));
        event.setBody(format("{ \"password\": \"%s\", \"email\": \"%s\" }", PASSWORD, EMAIL));

        usingValidSession();
        usingDefaultVectorOfTrust();

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.INVALID_CREDENTIALS,
                        CLIENT_SESSION_ID,
                        session.getSessionId(),
                        "",
                        "",
                        EMAIL,
                        "123.123.123.123",
                        "",
                        PersistentIdHelper.PERSISTENT_ID_UNKNOWN_VALUE);

        assertThat(result, hasStatus(401));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1008));
    }

    @ParameterizedTest
    @EnumSource(MFAMethodType.class)
    void shouldReturn401IfMigratedUserHasInvalidCredentials(MFAMethodType mfaMethodType) {
        String legacySubjectId = new Subject().getValue();
        UserProfile userProfile = generateUserProfile(legacySubjectId);
        when(authenticationService.getUserProfileByEmailMaybe(EMAIL))
                .thenReturn(Optional.of(userProfile));

        UserCredentials applicableUserCredentials = usingApplicableUserCredentials(mfaMethodType);

        when(userMigrationService.processMigratedUser(applicableUserCredentials, PASSWORD))
                .thenReturn(false);
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(
                Map.of(
                        "Session-Id",
                        session.getSessionId(),
                        CLIENT_SESSION_ID_HEADER,
                        CLIENT_SESSION_ID));
        event.setBody(format("{ \"password\": \"%s\", \"email\": \"%s\" }", PASSWORD, EMAIL));
        usingValidSession();
        usingDefaultVectorOfTrust();

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(401));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1008));
    }

    @Test
    void shouldReturn400IfAnyRequestParametersAreMissing() {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(
                Map.of(
                        "Session-Id",
                        session.getSessionId(),
                        CLIENT_SESSION_ID_HEADER,
                        CLIENT_SESSION_ID));
        event.setBody(format("{ \"password\": \"%s\"}", PASSWORD));

        usingValidSession();
        usingDefaultVectorOfTrust();
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1001));
    }

    @Test
    void shouldReturn400IfSessionIdIsInvalid() {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(
                Map.of(
                        "Session-Id",
                        session.getSessionId(),
                        CLIENT_SESSION_ID_HEADER,
                        CLIENT_SESSION_ID));
        event.setBody(format("{ \"password\": \"%s\"}", PASSWORD));

        when(sessionService.getSessionFromRequestHeaders(event.getHeaders()))
                .thenReturn(Optional.empty());

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1000));
    }

    @Test
    void shouldReturn400IfUserDoesNotHaveAnAccount() {
        when(authenticationService.getUserProfileByEmailMaybe(EMAIL)).thenReturn(Optional.empty());
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setRequestContext(contextWithSourceIp("123.123.123.123"));
        event.setHeaders(
                Map.of(
                        "Session-Id",
                        session.getSessionId(),
                        CLIENT_SESSION_ID_HEADER,
                        CLIENT_SESSION_ID));
        event.setBody(format("{ \"password\": \"%s\", \"email\": \"%s\" }", PASSWORD, EMAIL));
        usingValidSession();
        usingDefaultVectorOfTrust();

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.NO_ACCOUNT_WITH_EMAIL,
                        CLIENT_SESSION_ID,
                        session.getSessionId(),
                        "",
                        "",
                        "",
                        "123.123.123.123",
                        "",
                        PersistentIdHelper.PERSISTENT_ID_UNKNOWN_VALUE);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1010));
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
        when(authenticationService.login(applicableUserCredentials, PASSWORD))
                .thenReturn(loginSuccessful);
        return applicableUserCredentials;
    }

    private UserProfile generateUserProfile(String legacySubjectId) {
        LocalDateTime localDateTime = LocalDateTime.now();
        Date currentDateTime = Date.from(localDateTime.atZone(ZoneId.of("UTC")).toInstant());
        return new UserProfile()
                .setEmail(EMAIL)
                .setEmailVerified(true)
                .setPhoneNumber(PHONE_NUMBER)
                .setPhoneNumberVerified(true)
                .setPublicSubjectID(new Subject().getValue())
                .setSubjectID(new Subject().getValue())
                .setLegacySubjectID(legacySubjectId)
                .setTermsAndConditions(new TermsAndConditions("1.0", currentDateTime.toString()));
    }

    private ClientRegistry generateClientRegistry() {
        return new ClientRegistry()
                .withClientID(CLIENT_ID.getValue())
                .withConsentRequired(false)
                .withClientName("test-client")
                .withSectorIdentifierUri("https://test.com")
                .withSubjectType("public");
    }

    private void usingDefaultVectorOfTrust() {
        VectorOfTrust vectorOfTrust =
                VectorOfTrust.parseFromAuthRequestAttribute(
                        Collections.singletonList(jsonArrayOf("Cl.Cm")));
        when(clientSession.getEffectiveVectorOfTrust()).thenReturn(vectorOfTrust);
    }
}
