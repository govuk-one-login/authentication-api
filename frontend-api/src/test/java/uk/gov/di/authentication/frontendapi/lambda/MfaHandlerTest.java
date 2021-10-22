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
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.frontendapi.services.AwsSqsClient;
import uk.gov.di.authentication.shared.entity.BaseAPIResponse;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.ClientSession;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.NotifyRequest;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.SessionState;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.CodeGeneratorService;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.SessionService;

import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.shared.entity.NotificationType.MFA_SMS;
import static uk.gov.di.authentication.shared.entity.SessionState.MFA_CODE_MAX_RETRIES_REACHED;
import static uk.gov.di.authentication.shared.entity.SessionState.MFA_SMS_CODE_SENT;
import static uk.gov.di.authentication.shared.entity.SessionState.MFA_SMS_MAX_CODES_SENT;
import static uk.gov.di.authentication.shared.entity.SessionState.UPLIFT_REQUIRED_CM;
import static uk.gov.di.authentication.shared.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.authentication.shared.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;
import static uk.gov.di.authentication.shared.services.CodeStorageService.CODE_BLOCKED_KEY_PREFIX;
import static uk.gov.di.authentication.shared.services.CodeStorageService.CODE_REQUEST_BLOCKED_KEY_PREFIX;

public class MfaHandlerTest {

    private MfaHandler handler;
    private static final String PHONE_NUMBER = "01234567890";
    private static final String TEST_EMAIL_ADDRESS = "test@test.com";
    private static final String CODE = "123456";
    private static final long CODE_EXPIRY_TIME = 900;
    private static final String TEST_CLIENT_ID = "test-client-id";
    private static final URI REDIRECT_URI = URI.create("http://localhost/redirect");
    private final Context context = mock(Context.class);
    private final SessionService sessionService = mock(SessionService.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final CodeGeneratorService codeGeneratorService = mock(CodeGeneratorService.class);
    private final CodeStorageService codeStorageService = mock(CodeStorageService.class);
    private final AuthenticationService authenticationService = mock(AuthenticationService.class);
    private final ClientSessionService clientSessionService = mock(ClientSessionService.class);
    private final ClientService clientService = mock(ClientService.class);
    private final ClientSession clientSession = mock(ClientSession.class);
    private final AwsSqsClient sqsClient = mock(AwsSqsClient.class);
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final Session session =
            new Session("a-session-id")
                    .setEmailAddress(TEST_EMAIL_ADDRESS)
                    .setState(SessionState.LOGGED_IN);
    private final ClientRegistry testClientRegistry =
            new ClientRegistry()
                    .setTestClient(true)
                    .setClientID(TEST_CLIENT_ID)
                    .setTestClientEmailAllowlist(
                            List.of(
                                    "joe.bloggs@digital.cabinet-office.gov.uk",
                                    TEST_EMAIL_ADDRESS,
                                    "jb2@digital.cabinet-office.gov.uk"));

    @BeforeEach
    public void setUp() {
        when(configurationService.getCodeExpiry()).thenReturn(CODE_EXPIRY_TIME);
        when(configurationService.getCodeMaxRetries()).thenReturn(5);
        handler =
                new MfaHandler(
                        configurationService,
                        sessionService,
                        codeGeneratorService,
                        codeStorageService,
                        clientSessionService,
                        clientService,
                        authenticationService,
                        sqsClient);
        when(clientService.getClient(TEST_CLIENT_ID)).thenReturn(Optional.of(testClientRegistry));
    }

    @Test
    public void shouldReturn200ForSuccessfulMfaRequest() throws JsonProcessingException {
        usingValidSession();
        when(authenticationService.getPhoneNumber(TEST_EMAIL_ADDRESS))
                .thenReturn(Optional.of(PHONE_NUMBER));
        when(codeGeneratorService.sixDigitCode()).thenReturn(CODE);
        NotifyRequest notifyRequest = new NotifyRequest(PHONE_NUMBER, MFA_SMS, CODE);
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("Session-Id", session.getSessionId()));
        event.setBody(format("{ \"email\": \"%s\"}", TEST_EMAIL_ADDRESS));

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        verify(sqsClient).send(new ObjectMapper().writeValueAsString(notifyRequest));
        verify(codeStorageService).saveOtpCode(TEST_EMAIL_ADDRESS, CODE, CODE_EXPIRY_TIME, MFA_SMS);
        assertThat(result, hasStatus(200));
    }

    @Test
    public void shouldAllowMfaRequestDuringUplift() throws JsonProcessingException {
        usingValidSession();
        session.setState(UPLIFT_REQUIRED_CM);

        when(authenticationService.getPhoneNumber(TEST_EMAIL_ADDRESS))
                .thenReturn(Optional.of(PHONE_NUMBER));
        when(codeGeneratorService.sixDigitCode()).thenReturn(CODE);
        NotifyRequest notifyRequest = new NotifyRequest(PHONE_NUMBER, MFA_SMS, CODE);
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("Session-Id", session.getSessionId()));
        event.setBody(format("{ \"email\": \"%s\"}", TEST_EMAIL_ADDRESS));

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        verify(sqsClient).send(new ObjectMapper().writeValueAsString(notifyRequest));
        verify(codeStorageService).saveOtpCode(TEST_EMAIL_ADDRESS, CODE, CODE_EXPIRY_TIME, MFA_SMS);
        assertThat(result, hasStatus(200));
    }

    @Test
    public void shouldReturn400WhenSessionIdIsInvalid() {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("Session-Id", session.getSessionId()));
        event.setBody(format("{ \"email\": \"%s\"}", TEST_EMAIL_ADDRESS));

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
    }

    @Test
    public void shouldReturnErrorResponseWhenUsersPhoneNumberIsNotStored() {
        usingValidSession();
        when(authenticationService.getPhoneNumber(TEST_EMAIL_ADDRESS)).thenReturn(Optional.empty());
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("Session-Id", session.getSessionId()));
        event.setBody(format("{ \"email\": \"%s\"}", TEST_EMAIL_ADDRESS));

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1014));
    }

    @Test
    public void shouldReturn400IfUserTransitionsFromWrongState() {
        session.setState(SessionState.NEW);

        usingValidSession();

        when(authenticationService.getPhoneNumber(TEST_EMAIL_ADDRESS))
                .thenReturn(Optional.of(PHONE_NUMBER));
        when(codeGeneratorService.sixDigitCode()).thenReturn(CODE);

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("Session-Id", session.getSessionId()));
        event.setBody(format("{ \"email\": \"%s\"}", TEST_EMAIL_ADDRESS));

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        verifyNoInteractions(sqsClient);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1017));
    }

    @Test
    public void shouldReturn400IfUserHasReachedTheMfaCodeRequestLimit()
            throws JsonProcessingException {
        usingValidSession();
        session.setState(MFA_SMS_CODE_SENT);
        session.incrementCodeRequestCount();
        session.incrementCodeRequestCount();
        session.incrementCodeRequestCount();
        session.incrementCodeRequestCount();
        session.incrementCodeRequestCount();

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("Session-Id", session.getSessionId()));
        event.setBody(format("{ \"email\": \"%s\"}", TEST_EMAIL_ADDRESS));

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertEquals(400, result.getStatusCode());
        BaseAPIResponse codeResponse =
                objectMapper.readValue(result.getBody(), BaseAPIResponse.class);
        assertEquals(SessionState.MFA_SMS_MAX_CODES_SENT, codeResponse.getSessionState());
        verify(codeStorageService)
                .saveBlockedForEmail(
                        TEST_EMAIL_ADDRESS, CODE_REQUEST_BLOCKED_KEY_PREFIX, CODE_EXPIRY_TIME);
    }

    @Test
    public void shouldReturn400IfUserIsBlockedFromRequestingAnyMoreMfaCodes()
            throws JsonProcessingException {
        usingValidSession();
        session.setState(MFA_SMS_MAX_CODES_SENT);
        when(codeStorageService.isBlockedForEmail(
                        TEST_EMAIL_ADDRESS, CODE_REQUEST_BLOCKED_KEY_PREFIX))
                .thenReturn(true);

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("Session-Id", session.getSessionId()));
        event.setBody(format("{ \"email\": \"%s\"}", TEST_EMAIL_ADDRESS));

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertEquals(400, result.getStatusCode());
        BaseAPIResponse codeResponse =
                objectMapper.readValue(result.getBody(), BaseAPIResponse.class);
        assertEquals(SessionState.MFA_CODE_REQUESTS_BLOCKED, codeResponse.getSessionState());
    }

    @Test
    public void shouldReturn400IfUserIsBlockedFromAttemptingMfaCodes()
            throws JsonProcessingException {
        usingValidSession();
        session.setState(MFA_CODE_MAX_RETRIES_REACHED);
        when(codeStorageService.isBlockedForEmail(TEST_EMAIL_ADDRESS, CODE_BLOCKED_KEY_PREFIX))
                .thenReturn(true);

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("Session-Id", session.getSessionId()));
        event.setBody(format("{ \"email\": \"%s\"}", TEST_EMAIL_ADDRESS));

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertEquals(400, result.getStatusCode());
        BaseAPIResponse codeResponse =
                objectMapper.readValue(result.getBody(), BaseAPIResponse.class);
        assertEquals(MFA_CODE_MAX_RETRIES_REACHED, codeResponse.getSessionState());
    }

    @Test
    public void shouldReturn200AndNotSendMessageForSuccessfulMfaRequestOnTestClient()
            throws JsonProcessingException {
        usingValidSession();
        usingValidClientSession(TEST_CLIENT_ID);
        when(configurationService.isTestClientsEnabled()).thenReturn(true);
        when(authenticationService.getPhoneNumber(TEST_EMAIL_ADDRESS))
                .thenReturn(Optional.of(PHONE_NUMBER));
        when(codeGeneratorService.sixDigitCode()).thenReturn(CODE);
        NotifyRequest notifyRequest = new NotifyRequest(PHONE_NUMBER, MFA_SMS, CODE);
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("Session-Id", session.getSessionId()));
        event.setBody(format("{ \"email\": \"%s\"}", TEST_EMAIL_ADDRESS));

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        verify(sqsClient, never()).send(objectMapper.writeValueAsString(notifyRequest));
        verify(codeStorageService).saveOtpCode(TEST_EMAIL_ADDRESS, CODE, CODE_EXPIRY_TIME, MFA_SMS);
        assertThat(result, hasStatus(200));
    }

    private void usingValidSession() {
        when(sessionService.getSessionFromRequestHeaders(anyMap()))
                .thenReturn(Optional.of(session));
    }

    private void usingValidClientSession(String clientId) {
        when(clientSessionService.getClientSessionFromRequestHeaders(anyMap()))
                .thenReturn(Optional.of(clientSession));
        when(clientSession.getAuthRequestParams())
                .thenReturn(withAuthenticationRequest(clientId).toParameters());
    }

    private AuthenticationRequest withAuthenticationRequest(String clientId) {
        Scope scope = new Scope();
        scope.add(OIDCScopeValue.OPENID);
        return new AuthenticationRequest.Builder(
                        new ResponseType(ResponseType.Value.CODE),
                        scope,
                        new ClientID(clientId),
                        REDIRECT_URI)
                .state(new State())
                .nonce(new Nonce())
                .build();
    }
}
