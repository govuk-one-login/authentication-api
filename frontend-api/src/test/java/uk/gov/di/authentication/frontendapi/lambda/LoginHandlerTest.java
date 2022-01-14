package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
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
import uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent;
import uk.gov.di.authentication.frontendapi.entity.LoginResponse;
import uk.gov.di.authentication.frontendapi.helpers.RedactPhoneNumberHelper;
import uk.gov.di.authentication.frontendapi.services.UserMigrationService;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.ClientSession;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.TermsAndConditions;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.entity.VectorOfTrust;
import uk.gov.di.authentication.shared.helpers.IdGenerator;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
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
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.not;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.sharedtest.helper.JsonArrayHelper.jsonArrayOf;
import static uk.gov.di.authentication.sharedtest.helper.RequestEventHelper.contextWithSourceIp;
import static uk.gov.di.authentication.sharedtest.logging.LogEventMatcher.withMessageContaining;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class LoginHandlerTest {

    private static final String EMAIL = "joe.bloggs@test.com";
    private static final String PASSWORD = "computer-1";
    private static final String PHONE_NUMBER = "01234567890";
    private static final ClientID CLIENT_ID = new ClientID();
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

    private final Session session = new Session(IdGenerator.generate());

    @RegisterExtension
    public final CaptureLoggingExtension logging = new CaptureLoggingExtension(LoginHandler.class);

    @AfterEach
    public void tearDown() {
        assertThat(logging.events(), not(hasItem(withMessageContaining(session.getSessionId()))));
    }

    @BeforeEach
    public void setUp() {
        when(configurationService.getMaxPasswordRetries()).thenReturn(5);
        when(clientSessionService.getClientSessionFromRequestHeaders(any()))
                .thenReturn(Optional.of(clientSession));
        when(context.getAwsRequestId()).thenReturn("aws-session-id");

        VectorOfTrust vectorOfTrust =
                VectorOfTrust.parseFromAuthRequestAttribute(
                        Collections.singletonList(jsonArrayOf("Cl.Cm")));
        when(clientSession.getEffectiveVectorOfTrust()).thenReturn(vectorOfTrust);
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
                        auditService);
    }

    @Test
    public void shouldReturn200IfLoginIsSuccessful() throws JsonProcessingException {
        when(configurationService.getTermsAndConditionsVersion()).thenReturn("1.0");
        String persistentId = "some-persistent-id-value";
        Map<String, String> headers = new HashMap<>();
        headers.put(PersistentIdHelper.PERSISTENT_ID_HEADER_NAME, persistentId);
        headers.put("Session-Id", session.getSessionId());
        UserProfile userProfile = generateUserProfile(null);
        when(authenticationService.getUserProfileByEmailMaybe(EMAIL))
                .thenReturn(Optional.of(userProfile));
        when(userMigrationService.userHasBeenPartlyMigrated(
                        userProfile.getLegacySubjectID(), EMAIL))
                .thenReturn(false);
        when(authenticationService.login(EMAIL, PASSWORD)).thenReturn(true);
        when(clientSession.getAuthRequestParams())
                .thenReturn(generateAuthRequest(Optional.empty()).toParameters());
        usingValidSession();
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setRequestContext(contextWithSourceIp("123.123.123.123"));
        event.setHeaders(headers);
        event.setBody(
                format(
                        "{ \"password\": \"%s\", \"email\": \"%s\" }",
                        PASSWORD, EMAIL.toUpperCase()));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(200));

        LoginResponse response =
                new ObjectMapper().readValue(result.getBody(), LoginResponse.class);
        assertThat(
                response.getRedactedPhoneNumber(),
                equalTo(RedactPhoneNumberHelper.redactPhoneNumber(PHONE_NUMBER)));
        assertThat(response.getLatestTermsAndConditionsAccepted(), equalTo(true));
        verify(authenticationService).getUserProfileByEmail(EMAIL);

        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.LOG_IN_SUCCESS,
                        "aws-session-id",
                        session.getSessionId(),
                        "",
                        userProfile.getSubjectID(),
                        userProfile.getEmail(),
                        "123.123.123.123",
                        userProfile.getPhoneNumber(),
                        persistentId);
    }

    @Test
    public void shouldReturn200IfLoginIsSuccessfulAndTermsAndConditionsNotAccepted()
            throws JsonProcessingException {
        when(configurationService.getTermsAndConditionsVersion()).thenReturn("2.0");
        String persistentId = "some-persistent-id-value";
        Map<String, String> headers = new HashMap<>();
        headers.put(PersistentIdHelper.PERSISTENT_ID_HEADER_NAME, persistentId);
        headers.put("Session-Id", session.getSessionId());
        UserProfile userProfile = generateUserProfile(null);
        when(authenticationService.getUserProfileByEmailMaybe(EMAIL))
                .thenReturn(Optional.of(userProfile));
        when(userMigrationService.userHasBeenPartlyMigrated(
                        userProfile.getLegacySubjectID(), EMAIL))
                .thenReturn(false);
        when(authenticationService.login(EMAIL, PASSWORD)).thenReturn(true);
        when(clientSession.getAuthRequestParams())
                .thenReturn(generateAuthRequest(Optional.empty()).toParameters());
        usingValidSession();
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setRequestContext(contextWithSourceIp("123.123.123.123"));
        event.setHeaders(headers);
        event.setBody(
                format(
                        "{ \"password\": \"%s\", \"email\": \"%s\" }",
                        PASSWORD, EMAIL.toUpperCase()));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(200));

        LoginResponse response =
                new ObjectMapper().readValue(result.getBody(), LoginResponse.class);
        assertThat(
                response.getRedactedPhoneNumber(),
                equalTo(RedactPhoneNumberHelper.redactPhoneNumber(PHONE_NUMBER)));
        assertThat(response.getLatestTermsAndConditionsAccepted(), equalTo(false));
        verify(authenticationService).getUserProfileByEmailMaybe(EMAIL);

        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.LOG_IN_SUCCESS,
                        "aws-session-id",
                        session.getSessionId(),
                        "",
                        userProfile.getSubjectID(),
                        userProfile.getEmail(),
                        "123.123.123.123",
                        userProfile.getPhoneNumber(),
                        persistentId);

        verify(sessionService)
                .save(argThat(session -> session.isNewAccount() == Session.AccountState.EXISTING));
    }

    @Test
    public void shouldReturn200IfMigratedUserHasBeenProcessesSuccessfully()
            throws JsonProcessingException {
        when(configurationService.getTermsAndConditionsVersion()).thenReturn("1.0");
        String legacySubjectId = new Subject().getValue();
        UserProfile userProfile = generateUserProfile(legacySubjectId);
        when(authenticationService.getUserProfileByEmailMaybe(EMAIL))
                .thenReturn(Optional.of(userProfile));
        when(userMigrationService.userHasBeenPartlyMigrated(
                        userProfile.getLegacySubjectID(), EMAIL))
                .thenReturn(true);
        when(userMigrationService.processMigratedUser(EMAIL, PASSWORD)).thenReturn(true);
        when(clientSession.getAuthRequestParams())
                .thenReturn(generateAuthRequest(Optional.empty()).toParameters());
        usingValidSession();
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("Session-Id", session.getSessionId()));
        event.setBody(format("{ \"password\": \"%s\", \"email\": \"%s\" }", PASSWORD, EMAIL));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(200));

        LoginResponse response =
                new ObjectMapper().readValue(result.getBody(), LoginResponse.class);
        assertThat(response.getLatestTermsAndConditionsAccepted(), equalTo(true));
        assertThat(
                response.getRedactedPhoneNumber(),
                equalTo(RedactPhoneNumberHelper.redactPhoneNumber(PHONE_NUMBER)));

        verify(sessionService)
                .save(argThat(session -> session.isNewAccount() == Session.AccountState.EXISTING));
    }

    @Test
    public void shouldReturn200IfPasswordIsEnteredAgain() throws JsonProcessingException {
        UserProfile userProfile = generateUserProfile(null);
        when(authenticationService.getUserProfileByEmailMaybe(EMAIL))
                .thenReturn(Optional.of(userProfile));
        when(userMigrationService.userHasBeenPartlyMigrated(
                        userProfile.getLegacySubjectID(), EMAIL))
                .thenReturn(false);
        when(authenticationService.login(EMAIL, PASSWORD)).thenReturn(true);
        when(clientSession.getAuthRequestParams())
                .thenReturn(generateAuthRequest(Optional.empty()).toParameters());

        usingValidSession();

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("Session-Id", session.getSessionId()));
        event.setBody(format("{ \"password\": \"%s\", \"email\": \"%s\" }", PASSWORD, EMAIL));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(200));

        LoginResponse response =
                new ObjectMapper().readValue(result.getBody(), LoginResponse.class);
        assertThat(
                response.getRedactedPhoneNumber(),
                equalTo(RedactPhoneNumberHelper.redactPhoneNumber(PHONE_NUMBER)));

        verify(sessionService)
                .save(argThat(session -> session.isNewAccount() == Session.AccountState.EXISTING));
    }

    @Test
    public void shouldChangeStateToAccountTemporarilyLockedAfter5UnsuccessfulAttempts() {
        UserProfile userProfile = generateUserProfile(null);
        when(authenticationService.getUserProfileByEmailMaybe(EMAIL))
                .thenReturn(Optional.of(userProfile));
        when(userMigrationService.userHasBeenPartlyMigrated(
                        userProfile.getLegacySubjectID(), EMAIL))
                .thenReturn(false);
        when(authenticationService.login(EMAIL, PASSWORD)).thenReturn(false);
        when(codeStorageService.getIncorrectPasswordCount(EMAIL)).thenReturn(5);

        usingValidSession();
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("Session-Id", session.getSessionId()));
        event.setBody(format("{ \"password\": \"%s\", \"email\": \"%s\" }", PASSWORD, EMAIL));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));

        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1028));
    }

    @Test
    public void shouldKeepUserLockedWhenTheyEnterSuccessfulLoginRequestInNewSession() {
        UserProfile userProfile = generateUserProfile(null);
        when(authenticationService.getUserProfileByEmailMaybe(EMAIL))
                .thenReturn(Optional.of(userProfile));
        when(userMigrationService.userHasBeenPartlyMigrated(
                        userProfile.getLegacySubjectID(), EMAIL))
                .thenReturn(false);
        when(authenticationService.login(EMAIL, PASSWORD)).thenReturn(true);
        when(codeStorageService.getIncorrectPasswordCount(EMAIL)).thenReturn(5);

        usingValidSession();
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setRequestContext(contextWithSourceIp("123.123.123.123"));
        event.setHeaders(Map.of("Session-Id", session.getSessionId()));
        event.setBody(format("{ \"password\": \"%s\", \"email\": \"%s\" }", PASSWORD, EMAIL));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1028));

        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.ACCOUNT_TEMPORARILY_LOCKED,
                        "aws-session-id",
                        session.getSessionId(),
                        "",
                        userProfile.getSubjectID(),
                        userProfile.getEmail(),
                        "123.123.123.123",
                        userProfile.getPhoneNumber(),
                        PersistentIdHelper.PERSISTENT_ID_UNKNOWN_VALUE);
    }

    @Test
    public void shouldRemoveIncorrectPasswordCountRemovesUponSuccessfulLogin()
            throws JsonProcessingException {
        UserProfile userProfile = generateUserProfile(null);
        when(authenticationService.getUserProfileByEmailMaybe(EMAIL))
                .thenReturn(Optional.of(userProfile));
        when(userMigrationService.userHasBeenPartlyMigrated(
                        userProfile.getLegacySubjectID(), EMAIL))
                .thenReturn(false);
        when(authenticationService.login(EMAIL, PASSWORD)).thenReturn(false);
        when(codeStorageService.getIncorrectPasswordCount(EMAIL)).thenReturn(4);

        usingValidSession();
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("Session-Id", session.getSessionId()));
        event.setBody(format("{ \"password\": \"%s\", \"email\": \"%s\" }", PASSWORD, EMAIL));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        when(authenticationService.login(EMAIL, PASSWORD)).thenReturn(true);
        when(clientSession.getAuthRequestParams())
                .thenReturn(generateAuthRequest(Optional.empty()).toParameters());

        APIGatewayProxyResponseEvent result2 = handler.handleRequest(event, context);

        assertThat(result2, hasStatus(200));

        LoginResponse response =
                new ObjectMapper().readValue(result2.getBody(), LoginResponse.class);
    }

    @Test
    public void shouldReturn401IfUserHasInvalidCredentials() {
        UserProfile userProfile = generateUserProfile(null);
        when(authenticationService.getUserProfileByEmailMaybe(EMAIL))
                .thenReturn(Optional.of(userProfile));
        when(userMigrationService.userHasBeenPartlyMigrated(
                        userProfile.getLegacySubjectID(), EMAIL))
                .thenReturn(false);
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setRequestContext(contextWithSourceIp("123.123.123.123"));
        event.setHeaders(Map.of("Session-Id", session.getSessionId()));
        event.setBody(format("{ \"password\": \"%s\", \"email\": \"%s\" }", PASSWORD, EMAIL));
        when(authenticationService.login(EMAIL, PASSWORD)).thenReturn(false);
        usingValidSession();

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.INVALID_CREDENTIALS,
                        "aws-session-id",
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

    @Test
    public void shouldReturn401IfMigratedUserHasInvalidCredentials() {
        String legacySubjectId = new Subject().getValue();
        UserProfile userProfile = generateUserProfile(legacySubjectId);
        when(authenticationService.getUserProfileByEmailMaybe(EMAIL))
                .thenReturn(Optional.of(userProfile));
        when(userMigrationService.userHasBeenPartlyMigrated(
                        userProfile.getLegacySubjectID(), EMAIL))
                .thenReturn(true);
        when(userMigrationService.processMigratedUser(EMAIL, PASSWORD)).thenReturn(false);
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("Session-Id", session.getSessionId()));
        event.setBody(format("{ \"password\": \"%s\", \"email\": \"%s\" }", PASSWORD, EMAIL));
        usingValidSession();

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(401));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1008));
    }

    @Test
    public void shouldReturn400IfAnyRequestParametersAreMissing() {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("Session-Id", session.getSessionId()));
        event.setBody(format("{ \"password\": \"%s\"}", PASSWORD));

        when(authenticationService.login(EMAIL, PASSWORD)).thenReturn(false);
        usingValidSession();
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1001));
    }

    @Test
    public void shouldReturn400IfSessionIdIsInvalid() {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("Session-Id", session.getSessionId()));
        event.setBody(format("{ \"password\": \"%s\"}", PASSWORD));

        when(authenticationService.login(EMAIL, PASSWORD)).thenReturn(false);
        when(sessionService.getSessionFromRequestHeaders(event.getHeaders()))
                .thenReturn(Optional.empty());

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1000));
    }

    @Test
    public void shouldReturn400IfUserDoesNotHaveAnAccount() {
        when(authenticationService.getUserProfileByEmailMaybe(EMAIL)).thenReturn(Optional.empty());
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setRequestContext(contextWithSourceIp("123.123.123.123"));
        event.setHeaders(Map.of("Session-Id", session.getSessionId()));
        event.setBody(format("{ \"password\": \"%s\", \"email\": \"%s\" }", PASSWORD, EMAIL));
        usingValidSession();

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.NO_ACCOUNT_WITH_EMAIL,
                        "aws-session-id",
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

    @Test
    public void shouldSetSessionCredentialStrengthIfClientSessionsVtrIsLow() {
        UserProfile userProfile = generateUserProfile(null);
        when(authenticationService.getUserProfileByEmailMaybe(EMAIL))
                .thenReturn(Optional.of(userProfile));
        when(userMigrationService.userHasBeenPartlyMigrated(
                        userProfile.getLegacySubjectID(), EMAIL))
                .thenReturn(false);
        when(authenticationService.login(EMAIL, PASSWORD)).thenReturn(true);
        when(clientSession.getAuthRequestParams())
                .thenReturn(generateAuthRequest(Optional.empty()).toParameters());

        VectorOfTrust vectorOfTrust =
                VectorOfTrust.parseFromAuthRequestAttribute(
                        Collections.singletonList(jsonArrayOf("Cl")));
        when(clientSession.getEffectiveVectorOfTrust()).thenReturn(vectorOfTrust);

        usingValidSession();
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("Session-Id", session.getSessionId()));
        event.setBody(format("{ \"password\": \"%s\", \"email\": \"%s\" }", PASSWORD, EMAIL));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        ArgumentCaptor<Session> sessionArgumentCaptor = ArgumentCaptor.forClass(Session.class);
        verify(sessionService, times(1)).save(sessionArgumentCaptor.capture());

        Session session = sessionArgumentCaptor.getValue();
        assertThat(session.getCurrentCredentialStrength(), equalTo(CredentialTrustLevel.LOW_LEVEL));
    }

    @Test
    public void shouldNotSetSessionCredentialStrengthIfClientSessionsVtrIsMedium() {
        UserProfile userProfile = generateUserProfile(null);
        when(authenticationService.getUserProfileByEmailMaybe(EMAIL))
                .thenReturn(Optional.of(userProfile));
        when(userMigrationService.userHasBeenPartlyMigrated(
                        userProfile.getLegacySubjectID(), EMAIL))
                .thenReturn(false);
        when(authenticationService.login(EMAIL, PASSWORD)).thenReturn(true);
        when(clientSession.getAuthRequestParams())
                .thenReturn(generateAuthRequest(Optional.empty()).toParameters());

        usingValidSession();
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("Session-Id", session.getSessionId()));
        event.setBody(format("{ \"password\": \"%s\", \"email\": \"%s\" }", PASSWORD, EMAIL));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        ArgumentCaptor<Session> sessionArgumentCaptor = ArgumentCaptor.forClass(Session.class);
        verify(sessionService, times(1)).save(sessionArgumentCaptor.capture());

        Session session = sessionArgumentCaptor.getValue();
        assertThat(session.getCurrentCredentialStrength(), nullValue());
    }

    private AuthenticationRequest generateAuthRequest(Optional<String> credentialTrustLevel) {
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
        credentialTrustLevel.ifPresent(t -> builder.customParameter("vtr", t));
        return builder.build();
    }

    private void usingValidSession() {
        when(sessionService.getSessionFromRequestHeaders(anyMap()))
                .thenReturn(Optional.of(session));
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
                .setClientID(CLIENT_ID.getValue())
                .setConsentRequired(false)
                .setClientName("test-client")
                .setSectorIdentifierUri("https://test.com")
                .setSubjectType("public");
    }
}
