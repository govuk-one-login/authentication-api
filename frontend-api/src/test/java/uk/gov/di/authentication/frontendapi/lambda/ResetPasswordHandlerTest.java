package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.ClientSession;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.NotificationType;
import uk.gov.di.authentication.shared.entity.NotifyRequest;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.UserCredentials;
import uk.gov.di.authentication.shared.helpers.Argon2EncoderHelper;
import uk.gov.di.authentication.shared.helpers.IdGenerator;
import uk.gov.di.authentication.shared.helpers.LocaleHelper.SupportedLanguage;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.AwsSqsClient;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.CommonPasswordsService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.SerializationService;
import uk.gov.di.authentication.shared.services.SessionService;
import uk.gov.di.authentication.shared.validation.PasswordValidator;

import java.net.URI;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.frontendapi.lambda.StartHandlerTest.CLIENT_SESSION_ID;
import static uk.gov.di.authentication.frontendapi.lambda.StartHandlerTest.CLIENT_SESSION_ID_HEADER;
import static uk.gov.di.authentication.sharedtest.helper.RequestEventHelper.contextWithSourceIp;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class ResetPasswordHandlerTest {

    private final AuthenticationService authenticationService = mock(AuthenticationService.class);
    private final AwsSqsClient sqsClient = mock(AwsSqsClient.class);
    private final CodeStorageService codeStorageService = mock(CodeStorageService.class);
    private final SessionService sessionService = mock(SessionService.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final ClientService clientService = mock(ClientService.class);
    private final ClientSessionService clientSessionService = mock(ClientSessionService.class);
    private final ClientSession clientSession = mock(ClientSession.class);
    private final AuditService auditService = mock(AuditService.class);
    private final CommonPasswordsService commonPasswordsService =
            mock(CommonPasswordsService.class);
    private final PasswordValidator passwordValidator = mock(PasswordValidator.class);
    private final Context context = mock(Context.class);
    private static final String TEST_CLIENT_ID = "test-client-id";
    private static final String NEW_PASSWORD = "Pa55word!";
    private static final String SUBJECT = "some-subject";
    private static final String EMAIL = "joe.bloggs@digital.cabinet-office.gov.uk";
    private static final String PERSISTENT_ID = "some-persistent-id-value";
    private static final Json objectMapper = SerializationService.getInstance();

    private ResetPasswordHandler handler;
    private final Session session = new Session(IdGenerator.generate()).setEmailAddress(EMAIL);

    private final ClientRegistry testClientRegistry =
            new ClientRegistry()
                    .withTestClient(true)
                    .withClientID(TEST_CLIENT_ID)
                    .withTestClientEmailAllowlist(
                            List.of(
                                    "joe.bloggs@digital.cabinet-office.gov.uk",
                                    EMAIL,
                                    "jb2@digital.cabinet-office.gov.uk"));

    @BeforeEach
    public void setUp() {
        doReturn(Optional.of(ErrorResponse.ERROR_1007))
                .when(passwordValidator)
                .validate("password");
        when(clientService.getClient(TEST_CLIENT_ID)).thenReturn(Optional.of(testClientRegistry));

        handler =
                new ResetPasswordHandler(
                        authenticationService,
                        sqsClient,
                        codeStorageService,
                        configurationService,
                        sessionService,
                        clientSessionService,
                        clientService,
                        auditService,
                        commonPasswordsService,
                        passwordValidator);
    }

    @Test
    void shouldReturn204ButNotPlaceMessageOnQueueForTestClient() {
        when(configurationService.isTestClientsEnabled()).thenReturn(true);
        when(authenticationService.getUserCredentialsFromEmail(EMAIL))
                .thenReturn(generateUserCredentials());
        usingValidSession();
        usingValidClientSession();
        Map<String, String> headers = new HashMap<>();
        headers.put(PersistentIdHelper.PERSISTENT_ID_HEADER_NAME, PERSISTENT_ID);
        headers.put("Session-Id", session.getSessionId());
        headers.put(CLIENT_SESSION_ID_HEADER, CLIENT_SESSION_ID);
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(headers);
        event.setBody(format("{ \"password\": \"%s\"}", NEW_PASSWORD));
        event.setRequestContext(contextWithSourceIp("123.123.123.123"));

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(204));
        verifyNoInteractions(sqsClient);
        verify(authenticationService, times(1)).updatePassword(EMAIL, NEW_PASSWORD);

        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.PASSWORD_RESET_SUCCESSFUL_FOR_TEST_CLIENT,
                        CLIENT_SESSION_ID,
                        session.getSessionId(),
                        TEST_CLIENT_ID,
                        AuditService.UNKNOWN,
                        EMAIL,
                        "123.123.123.123",
                        AuditService.UNKNOWN,
                        PERSISTENT_ID);
    }

    @Test
    public void shouldReturn204ForSuccessfulRequestWithNoCode() throws Json.JsonException {
        when(authenticationService.getUserCredentialsFromEmail(EMAIL))
                .thenReturn(generateUserCredentials());
        usingValidSession();
        NotifyRequest notifyRequest =
                new NotifyRequest(
                        EMAIL, NotificationType.PASSWORD_RESET_CONFIRMATION, SupportedLanguage.EN);
        Map<String, String> headers = new HashMap<>();
        headers.put(PersistentIdHelper.PERSISTENT_ID_HEADER_NAME, PERSISTENT_ID);
        headers.put("Session-Id", session.getSessionId());
        headers.put(CLIENT_SESSION_ID_HEADER, CLIENT_SESSION_ID);
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(headers);
        event.setBody(format("{ \"password\": \"%s\"}", NEW_PASSWORD));
        event.setRequestContext(contextWithSourceIp("123.123.123.123"));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(204));
        verify(sqsClient, times(1)).send(objectMapper.writeValueAsString(notifyRequest));
        verify(authenticationService, times(1)).updatePassword(EMAIL, NEW_PASSWORD);

        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.PASSWORD_RESET_SUCCESSFUL,
                        CLIENT_SESSION_ID,
                        session.getSessionId(),
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        EMAIL,
                        "123.123.123.123",
                        AuditService.UNKNOWN,
                        PERSISTENT_ID);
    }

    @Test
    public void shouldReturn204ForSuccessfulMigratedUserRequest() throws Json.JsonException {
        when(authenticationService.getUserCredentialsFromEmail(EMAIL))
                .thenReturn(generateMigratedUserCredentials());
        usingValidSession();
        NotifyRequest notifyRequest =
                new NotifyRequest(
                        EMAIL, NotificationType.PASSWORD_RESET_CONFIRMATION, SupportedLanguage.EN);
        Map<String, String> headers = new HashMap<>();
        headers.put(PersistentIdHelper.PERSISTENT_ID_HEADER_NAME, PERSISTENT_ID);
        headers.put("Session-Id", session.getSessionId());
        headers.put(CLIENT_SESSION_ID_HEADER, CLIENT_SESSION_ID);
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody(format("{ \"password\": \"%s\"}", NEW_PASSWORD));
        event.setHeaders(headers);
        event.setRequestContext(contextWithSourceIp("123.123.123.123"));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(204));
        verify(sqsClient, times(1)).send(objectMapper.writeValueAsString(notifyRequest));
        verify(authenticationService, times(1)).updatePassword(EMAIL, NEW_PASSWORD);
        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.PASSWORD_RESET_SUCCESSFUL,
                        CLIENT_SESSION_ID,
                        session.getSessionId(),
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        EMAIL,
                        "123.123.123.123",
                        AuditService.UNKNOWN,
                        PERSISTENT_ID);
    }

    @Test
    public void shouldReturn400ForRequestIsMissingPassword() {
        usingValidSession();
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody("{ }");
        event.setHeaders(Map.of("Session-Id", session.getSessionId()));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1001));
        verifyNoInteractions(auditService);
    }

    @Test
    public void shouldReturn400IfPasswordFailsValidation() {
        usingValidSession();
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody(format("{ \"password\": \"%s\"}", "password"));
        event.setHeaders(Map.of("Session-Id", session.getSessionId()));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1007));
        verify(authenticationService, never()).updatePassword(EMAIL, NEW_PASSWORD);
        verifyNoInteractions(auditService);
    }

    @Test
    public void shouldReturn400IfNewPasswordEqualsExistingPassword() throws Json.JsonException {
        usingValidSession();
        when(authenticationService.getUserCredentialsFromEmail(EMAIL))
                .thenReturn(generateUserCredentials(Argon2EncoderHelper.argon2Hash(NEW_PASSWORD)));
        NotifyRequest notifyRequest =
                new NotifyRequest(
                        EMAIL, NotificationType.PASSWORD_RESET_CONFIRMATION, SupportedLanguage.EN);
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody(format("{ \"password\": \"%s\"}", NEW_PASSWORD));
        event.setHeaders(Map.of("Session-Id", session.getSessionId()));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1024));
        verify(sqsClient, never()).send(objectMapper.writeValueAsString(notifyRequest));
        verify(authenticationService, never()).updatePassword(EMAIL, NEW_PASSWORD);
        verifyNoInteractions(auditService);
    }

    @Test
    public void shouldDeleteIncorrectPasswordCountOnSuccessfulRequest() {
        usingValidSession();
        when(authenticationService.getUserCredentialsFromEmail(EMAIL))
                .thenReturn(generateUserCredentials());
        when(codeStorageService.getIncorrectPasswordCount(EMAIL)).thenReturn(2);
        Map<String, String> headers = new HashMap<>();
        headers.put(PersistentIdHelper.PERSISTENT_ID_HEADER_NAME, PERSISTENT_ID);
        headers.put("Session-Id", session.getSessionId());
        headers.put(CLIENT_SESSION_ID_HEADER, CLIENT_SESSION_ID);
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody(format("{ \"password\": \"%s\"}", NEW_PASSWORD));
        event.setHeaders(headers);
        event.setRequestContext(contextWithSourceIp("123.123.123.123"));

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(204));
        verify(codeStorageService, times(1)).deleteIncorrectPasswordCount(EMAIL);
        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.PASSWORD_RESET_SUCCESSFUL,
                        CLIENT_SESSION_ID,
                        session.getSessionId(),
                        AuditService.UNKNOWN,
                        AuditService.UNKNOWN,
                        EMAIL,
                        "123.123.123.123",
                        AuditService.UNKNOWN,
                        PERSISTENT_ID);
    }

    @Test
    public void shouldReturn400WhenUserHasInvalidSession() {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("Session-Id", session.getSessionId()));
        event.setBody(format("{ \"password\": \"%s\"}", NEW_PASSWORD));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1000));
        verify(authenticationService, never()).updatePassword(EMAIL, NEW_PASSWORD);
        verifyNoInteractions(auditService);
    }

    private void usingValidClientSession() {
        var authRequest =
                new AuthenticationRequest.Builder(
                                new ResponseType(ResponseType.Value.CODE),
                                new Scope(OIDCScopeValue.OPENID),
                                new ClientID(TEST_CLIENT_ID),
                                URI.create("http://localhost/redirect"))
                        .state(new State())
                        .nonce(new Nonce())
                        .build();
        when(clientSessionService.getClientSessionFromRequestHeaders(anyMap()))
                .thenReturn(Optional.of(clientSession));
        when(clientSession.getAuthRequestParams()).thenReturn(authRequest.toParameters());
    }

    private UserCredentials generateUserCredentials() {
        return generateUserCredentials("old-password1");
    }

    private UserCredentials generateUserCredentials(String password) {
        return new UserCredentials().withEmail(EMAIL).withPassword(password).withSubjectID(SUBJECT);
    }

    private UserCredentials generateMigratedUserCredentials() {
        return new UserCredentials()
                .withEmail(EMAIL)
                .withMigratedPassword("old-password1")
                .withSubjectID(SUBJECT);
    }

    private void usingValidSession() {
        when(sessionService.getSessionFromRequestHeaders(anyMap()))
                .thenReturn(Optional.of(session));
    }
}
