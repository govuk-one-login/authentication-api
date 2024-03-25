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
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.mockito.Mockito;
import software.amazon.awssdk.core.exception.SdkClientException;
import uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.ClientSession;
import uk.gov.di.authentication.shared.entity.CodeRequestType;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.NotificationType;
import uk.gov.di.authentication.shared.entity.NotifyRequest;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.helpers.IdGenerator;
import uk.gov.di.authentication.shared.helpers.LocaleHelper.SupportedLanguage;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.AwsSqsClient;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.CodeGeneratorService;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.SerializationService;
import uk.gov.di.authentication.shared.services.SessionService;
import uk.gov.di.authentication.sharedtest.logging.CaptureLoggingExtension;

import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.frontendapi.lambda.StartHandlerTest.CLIENT_SESSION_ID;
import static uk.gov.di.authentication.frontendapi.lambda.StartHandlerTest.CLIENT_SESSION_ID_HEADER;
import static uk.gov.di.authentication.shared.entity.NotificationType.RESET_PASSWORD_WITH_CODE;
import static uk.gov.di.authentication.shared.services.AuditService.MetadataPair.pair;
import static uk.gov.di.authentication.shared.services.CodeStorageService.CODE_BLOCKED_KEY_PREFIX;
import static uk.gov.di.authentication.shared.services.CodeStorageService.CODE_REQUEST_BLOCKED_KEY_PREFIX;
import static uk.gov.di.authentication.sharedtest.helper.RequestEventHelper.contextWithSourceIp;
import static uk.gov.di.authentication.sharedtest.logging.LogEventMatcher.withMessageContaining;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;
import static uk.gov.di.authentication.sharedtest.matchers.JsonArgumentMatcher.containsJsonString;

class ResetPasswordRequestHandlerTest {

    private static final String TEST_EMAIL_ADDRESS = "joe.bloggs@digital.cabinet-office.gov.uk";
    private static final String TEST_SIX_DIGIT_CODE = "123456";
    private static final String PERSISTENT_ID = "some-persistent-id-value";
    private static final long CODE_EXPIRY_TIME = 900;
    private static final String TEST_CLIENT_ID = "test-client-id";
    private static final long LOCKOUT_DURATION = 799;
    private static final Json objectMapper = SerializationService.getInstance();
    private static final String PHONE_NUMBER = "01234567890";
    private static final AuditService.MetadataPair PASSWORD_RESET_COUNTER =
            pair("passwordResetCounter", 0);

    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final AwsSqsClient awsSqsClient = mock(AwsSqsClient.class);
    private final SessionService sessionService = mock(SessionService.class);
    private final ClientSession clientSession = mock(ClientSession.class);
    private final CodeGeneratorService codeGeneratorService = mock(CodeGeneratorService.class);
    private final CodeStorageService codeStorageService = mock(CodeStorageService.class);
    private final AuthenticationService authenticationService = mock(AuthenticationService.class);
    private final ClientSessionService clientSessionService = mock(ClientSessionService.class);
    private final ClientService clientService = mock(ClientService.class);
    private final AuditService auditService = mock(AuditService.class);
    private final Context context = mock(Context.class);

    private final ClientRegistry testClientRegistry =
            new ClientRegistry()
                    .withTestClient(true)
                    .withClientID(TEST_CLIENT_ID)
                    .withTestClientEmailAllowlist(
                            List.of(
                                    "joe.bloggs@digital.cabinet-office.gov.uk",
                                    TEST_EMAIL_ADDRESS,
                                    "jb2@digital.cabinet-office.gov.uk"));

    private final Session session =
            new Session(IdGenerator.generate()).setEmailAddress(TEST_EMAIL_ADDRESS);
    private final ResetPasswordRequestHandler handler =
            new ResetPasswordRequestHandler(
                    configurationService,
                    sessionService,
                    clientSessionService,
                    clientService,
                    authenticationService,
                    awsSqsClient,
                    codeGeneratorService,
                    codeStorageService,
                    auditService);

    @RegisterExtension
    public final CaptureLoggingExtension logging =
            new CaptureLoggingExtension(ResetPasswordRequestHandler.class);

    @AfterEach
    public void tearDown() {
        assertThat(
                logging.events(),
                not(hasItem(withMessageContaining(session.getSessionId(), TEST_EMAIL_ADDRESS))));
    }

    @BeforeEach
    void setup() {
        when(clientService.getClient(TEST_CLIENT_ID)).thenReturn(Optional.of(testClientRegistry));
        when(configurationService.getDefaultOtpCodeExpiry()).thenReturn(CODE_EXPIRY_TIME);
        when(codeGeneratorService.twentyByteEncodedRandomCode()).thenReturn(TEST_SIX_DIGIT_CODE);
        when(codeGeneratorService.sixDigitCode()).thenReturn(TEST_SIX_DIGIT_CODE);
        when(configurationService.getCodeMaxRetries()).thenReturn(5);
    }

    @Nested
    class WhenTheRequestIsValid {

        static final String validRequestBody = format("{ \"email\": \"%s\"}", TEST_EMAIL_ADDRESS);
        static NotifyRequest notifyRequest =
                new NotifyRequest(
                        TEST_EMAIL_ADDRESS,
                        RESET_PASSWORD_WITH_CODE,
                        TEST_SIX_DIGIT_CODE,
                        SupportedLanguage.EN);

        public static APIGatewayProxyRequestEvent validEvent;

        private boolean isSessionWithEmailSent(Session session) {
            return session.getEmailAddress().equals(TEST_EMAIL_ADDRESS);
        }

        @BeforeEach
        void setup() {
            validEvent = eventWithHeadersAndBody(validHeaders(), validRequestBody);
            Subject subject = new Subject("subject_1");
            when(authenticationService.getSubjectFromEmail(TEST_EMAIL_ADDRESS)).thenReturn(subject);
            when(authenticationService.getPhoneNumber(TEST_EMAIL_ADDRESS))
                    .thenReturn(Optional.of(PHONE_NUMBER));
        }

        @Test
        void shouldReturn200AndPutMessageOnQueueForAValidCodeFlowRequest()
                throws Json.JsonException {
            usingValidSession();

            APIGatewayProxyResponseEvent result = handler.handleRequest(validEvent, context);

            assertEquals(204, result.getStatusCode());

            verify(awsSqsClient)
                    .send(
                            argThat(
                                    containsJsonString(
                                            objectMapper.writeValueAsString(notifyRequest))));
            verify(codeStorageService)
                    .saveOtpCode(
                            TEST_EMAIL_ADDRESS,
                            TEST_SIX_DIGIT_CODE,
                            CODE_EXPIRY_TIME,
                            RESET_PASSWORD_WITH_CODE);
            verify(sessionService).save(argThat(this::isSessionWithEmailSent));
            verify(auditService)
                    .submitAuditEvent(
                            FrontendAuditableEvent.PASSWORD_RESET_REQUESTED,
                            CLIENT_SESSION_ID,
                            session.getSessionId(),
                            AuditService.UNKNOWN,
                            AuditService.UNKNOWN,
                            TEST_EMAIL_ADDRESS,
                            "123.123.123.123",
                            PHONE_NUMBER,
                            PERSISTENT_ID,
                            PASSWORD_RESET_COUNTER);
        }

        @Test
        void shouldUseExistingOtpCodeIfOneExists() throws Json.JsonException {
            when(codeStorageService.getOtpCode(any(String.class), any(NotificationType.class)))
                    .thenReturn(Optional.of(TEST_SIX_DIGIT_CODE));

            usingValidSession();
            APIGatewayProxyResponseEvent result = handler.handleRequest(validEvent, context);

            verify(codeGeneratorService, never()).sixDigitCode();
            verify(codeStorageService, never())
                    .saveOtpCode(
                            any(String.class),
                            any(String.class),
                            anyLong(),
                            any(NotificationType.class));
            verify(awsSqsClient).send(objectMapper.writeValueAsString(notifyRequest));
            assertThat(result, hasStatus(204));
        }

        @Test
        void shouldReturn200ButNotPutMessageOnQueueIfTestClient() {
            when(configurationService.isTestClientsEnabled()).thenReturn(true);

            usingValidSession();
            usingValidClientSession();
            var result = handler.handleRequest(validEvent, context);

            assertEquals(204, result.getStatusCode());

            verifyNoInteractions(awsSqsClient);
            verify(codeStorageService)
                    .saveOtpCode(
                            TEST_EMAIL_ADDRESS,
                            TEST_SIX_DIGIT_CODE,
                            CODE_EXPIRY_TIME,
                            RESET_PASSWORD_WITH_CODE);
            verify(sessionService).save(argThat(this::isSessionWithEmailSent));

            verify(auditService)
                    .submitAuditEvent(
                            FrontendAuditableEvent.PASSWORD_RESET_REQUESTED_FOR_TEST_CLIENT,
                            CLIENT_SESSION_ID,
                            session.getSessionId(),
                            TEST_CLIENT_ID,
                            AuditService.UNKNOWN,
                            TEST_EMAIL_ADDRESS,
                            "123.123.123.123",
                            PHONE_NUMBER,
                            PERSISTENT_ID,
                            PASSWORD_RESET_COUNTER);
        }

        @Test
        public void shouldReturn400IfUserIsBlockedFromRequestingAnyMorePasswordResets() {
            String sessionId = "1233455677";
            Session session = mock(Session.class);
            when(session.getEmailAddress()).thenReturn(TEST_EMAIL_ADDRESS);
            when(session.getSessionId()).thenReturn(sessionId);
            when(session.validateSession(TEST_EMAIL_ADDRESS)).thenReturn(true);
            when(session.getPasswordResetCount()).thenReturn(0);
            var codeRequestType =
                    CodeRequestType.getCodeRequestType(
                            RESET_PASSWORD_WITH_CODE, JourneyType.PASSWORD_RESET);
            var codeRequestBlockedKeyPrefix = CODE_REQUEST_BLOCKED_KEY_PREFIX + codeRequestType;
            when(codeStorageService.isBlockedForEmail(
                            TEST_EMAIL_ADDRESS, codeRequestBlockedKeyPrefix))
                    .thenReturn(true);
            when(sessionService.getSessionFromRequestHeaders(anyMap()))
                    .thenReturn(Optional.of(session));

            var result = handler.handleRequest(validEvent, context);

            assertEquals(400, result.getStatusCode());
            assertThat(result, hasJsonBody(ErrorResponse.ERROR_1023));
            verifyNoInteractions(awsSqsClient);
        }

        @Test
        public void shouldReturn400IfUserIsBlockedFromEnteringAnyMoreInvalidPasswordResetsOTPs() {
            String sessionId = "1233455677";
            Session session = mock(Session.class);
            when(session.getEmailAddress()).thenReturn(TEST_EMAIL_ADDRESS);
            when(session.getSessionId()).thenReturn(sessionId);
            when(session.validateSession(TEST_EMAIL_ADDRESS)).thenReturn(true);
            when(session.getPasswordResetCount()).thenReturn(0);
            var codeRequestType =
                    CodeRequestType.getCodeRequestType(
                            RESET_PASSWORD_WITH_CODE, JourneyType.PASSWORD_RESET);
            var codeRequestBlockedKeyPrefix = CODE_BLOCKED_KEY_PREFIX + codeRequestType;
            when(codeStorageService.isBlockedForEmail(
                            TEST_EMAIL_ADDRESS, codeRequestBlockedKeyPrefix))
                    .thenReturn(true);
            when(sessionService.getSessionFromRequestHeaders(anyMap()))
                    .thenReturn(Optional.of(session));

            var result = handler.handleRequest(validEvent, context);

            assertEquals(400, result.getStatusCode());
            assertThat(result, hasJsonBody(ErrorResponse.ERROR_1039));
            verifyNoInteractions(awsSqsClient);
        }

        @Test
        public void shouldReturn500IfMessageCannotBeSentToQueue() throws Json.JsonException {
            Subject subject = new Subject("subject_1");
            when(authenticationService.getSubjectFromEmail(TEST_EMAIL_ADDRESS)).thenReturn(subject);
            NotifyRequest notifyRequest =
                    new NotifyRequest(
                            TEST_EMAIL_ADDRESS,
                            RESET_PASSWORD_WITH_CODE,
                            TEST_SIX_DIGIT_CODE,
                            SupportedLanguage.EN);
            var serialisedRequest = objectMapper.writeValueAsString(notifyRequest);
            Mockito.doThrow(SdkClientException.class)
                    .when(awsSqsClient)
                    .send(eq(serialisedRequest));

            usingValidSession();
            APIGatewayProxyResponseEvent result = handler.handleRequest(validEvent, context);

            assertEquals(500, result.getStatusCode());
            assertTrue(result.getBody().contains("Error sending message to queue"));
        }

        @Test
        public void shouldReturn400IfUserHasExceededPasswordResetRequestCount() {
            Subject subject = new Subject("subject_1");
            String sessionId = "1233455677";
            when(authenticationService.getSubjectFromEmail(TEST_EMAIL_ADDRESS)).thenReturn(subject);
            when(configurationService.getLockoutDuration()).thenReturn(LOCKOUT_DURATION);
            Session session = mock(Session.class);
            when(session.getEmailAddress()).thenReturn(TEST_EMAIL_ADDRESS);
            when(session.getSessionId()).thenReturn(sessionId);
            when(session.validateSession(TEST_EMAIL_ADDRESS)).thenReturn(true);
            when(session.getPasswordResetCount()).thenReturn(5);

            when(sessionService.getSessionFromRequestHeaders(anyMap()))
                    .thenReturn(Optional.of(session));

            APIGatewayProxyResponseEvent result = handler.handleRequest(validEvent, context);
            var codeRequestType =
                    CodeRequestType.getCodeRequestType(
                            RESET_PASSWORD_WITH_CODE, JourneyType.PASSWORD_RESET);
            var codeRequestBlockedKeyPrefix = CODE_REQUEST_BLOCKED_KEY_PREFIX + codeRequestType;

            assertEquals(400, result.getStatusCode());
            assertThat(result, hasJsonBody(ErrorResponse.ERROR_1022));
            verify(codeStorageService)
                    .saveBlockedForEmail(
                            TEST_EMAIL_ADDRESS, codeRequestBlockedKeyPrefix, LOCKOUT_DURATION);
            verify(session).resetPasswordResetCount();
            verifyNoInteractions(awsSqsClient);
        }

        @Test
        void shouldReturn400WhenNoEmailIsPresentInSession() {
            when(authenticationService.getPhoneNumber(TEST_EMAIL_ADDRESS))
                    .thenReturn(Optional.of(PHONE_NUMBER));
            when(sessionService.getSessionFromRequestHeaders(anyMap()))
                    .thenReturn(Optional.of(new Session(IdGenerator.generate())));

            APIGatewayProxyResponseEvent result = handler.handleRequest(validEvent, context);

            assertEquals(400, result.getStatusCode());
            verifyNoInteractions(awsSqsClient);
            verifyNoInteractions(codeStorageService);
            verifyNoInteractions(auditService);
        }
    }

    @Nested
    class WhenRequestIsInvalid {
        @Test
        void shouldReturn400IfInvalidSessionProvided() {
            var body = format("{ \"email\": \"%s\" }", TEST_EMAIL_ADDRESS);
            APIGatewayProxyRequestEvent event = eventWithHeadersAndBody(Map.of(), body);
            APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

            assertEquals(400, result.getStatusCode());

            verify(awsSqsClient, never()).send(anyString());
            verify(codeStorageService, never())
                    .saveOtpCode(anyString(), anyString(), anyLong(), any(NotificationType.class));
            verify(sessionService, never()).save(any());
            verifyNoInteractions(awsSqsClient);
        }

        @Test
        public void shouldReturn400IfRequestIsMissingEmail() {
            usingValidSession();
            var body = "{ }";
            APIGatewayProxyRequestEvent event = eventWithHeadersAndBody(validHeaders(), body);
            APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

            assertEquals(400, result.getStatusCode());
            assertThat(result, hasJsonBody(ErrorResponse.ERROR_1001));
            verifyNoInteractions(awsSqsClient);
        }
    }

    private void usingValidSession() {
        when(sessionService.getSessionFromRequestHeaders(anyMap()))
                .thenReturn(Optional.of(session));
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

    private Map<String, String> validHeaders() {
        return Map.of(
                PersistentIdHelper.PERSISTENT_ID_HEADER_NAME,
                PERSISTENT_ID,
                "Session-Id",
                session.getSessionId(),
                CLIENT_SESSION_ID_HEADER,
                CLIENT_SESSION_ID);
    }

    private APIGatewayProxyRequestEvent eventWithHeadersAndBody(
            Map<String, String> headers, String body) {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setRequestContext(contextWithSourceIp("123.123.123.123"));
        event.setHeaders(headers);
        event.setBody(body);
        return event;
    }
}
