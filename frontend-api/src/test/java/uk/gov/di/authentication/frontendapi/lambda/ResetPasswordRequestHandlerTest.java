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
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent;
import uk.gov.di.authentication.frontendapi.entity.PasswordResetType;
import uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.ClientSession;
import uk.gov.di.authentication.shared.entity.CodeRequestType;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.MFAMethod;
import uk.gov.di.authentication.shared.entity.MFAMethodType;
import uk.gov.di.authentication.shared.entity.NotificationType;
import uk.gov.di.authentication.shared.entity.NotifyRequest;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.UserCredentials;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.entity.VectorOfTrust;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.helpers.IdGenerator;
import uk.gov.di.authentication.shared.helpers.LocaleHelper.SupportedLanguage;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.helpers.SaltHelper;
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
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

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
import static uk.gov.di.authentication.frontendapi.helpers.ApiGatewayProxyRequestHelper.apiRequestEventWithHeadersAndBody;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.CLIENT_SESSION_ID;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.DI_PERSISTENT_SESSION_ID;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.ENCODED_DEVICE_DETAILS;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.IP_ADDRESS;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.SESSION_ID;
import static uk.gov.di.authentication.frontendapi.helpers.CommonTestVariables.VALID_HEADERS;
import static uk.gov.di.authentication.shared.entity.NotificationType.RESET_PASSWORD_WITH_CODE;
import static uk.gov.di.authentication.shared.lambda.BaseFrontendHandler.TXMA_AUDIT_ENCODED_HEADER;
import static uk.gov.di.authentication.shared.services.AuditService.MetadataPair.pair;
import static uk.gov.di.authentication.shared.services.CodeStorageService.CODE_BLOCKED_KEY_PREFIX;
import static uk.gov.di.authentication.shared.services.CodeStorageService.CODE_REQUEST_BLOCKED_KEY_PREFIX;
import static uk.gov.di.authentication.sharedtest.logging.LogEventMatcher.withMessageContaining;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;
import static uk.gov.di.authentication.sharedtest.matchers.JsonArgumentMatcher.containsJsonString;

class ResetPasswordRequestHandlerTest {

    private static final String TEST_SIX_DIGIT_CODE = "123456";
    private static final long CODE_EXPIRY_TIME = 900;
    private static final String TEST_CLIENT_ID = "test-client-id";
    private static final long LOCKOUT_DURATION = 799;
    private static final Json objectMapper = SerializationService.getInstance();
    private static final AuditService.MetadataPair PASSWORD_RESET_COUNTER =
            pair("passwordResetCounter", 0);
    private static final AuditService.MetadataPair PASSWORD_RESET_TYPE_FORGOTTEN_PASSWORD =
            pair("passwordResetType", PasswordResetType.USER_FORGOTTEN_PASSWORD);

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
    private static final String CLIENT_ID = "test-client-id";
    private static final String CLIENT_NAME = "test-client-name";

    private final String expectedCommonSubject =
            ClientSubjectHelper.calculatePairwiseIdentifier(
                    new Subject().getValue(), "test.account.gov.uk", SaltHelper.generateNewSalt());

    private final ClientRegistry testClientRegistry =
            new ClientRegistry()
                    .withTestClient(true)
                    .withClientID(TEST_CLIENT_ID)
                    .withTestClientEmailAllowlist(
                            List.of(
                                    "joe.bloggs@digital.cabinet-office.gov.uk",
                                    CommonTestVariables.EMAIL,
                                    "jb2@digital.cabinet-office.gov.uk"));

    private final Session session =
            new Session(SESSION_ID)
                    .setEmailAddress(CommonTestVariables.EMAIL)
                    .setInternalCommonSubjectIdentifier(expectedCommonSubject);
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

    private final AuditContext auditContext =
            new AuditContext(
                    TEST_CLIENT_ID,
                    CLIENT_SESSION_ID,
                    SESSION_ID,
                    expectedCommonSubject,
                    CommonTestVariables.EMAIL,
                    IP_ADDRESS,
                    CommonTestVariables.UK_MOBILE_NUMBER,
                    DI_PERSISTENT_SESSION_ID,
                    Optional.of(ENCODED_DEVICE_DETAILS));

    @RegisterExtension
    public final CaptureLoggingExtension logging =
            new CaptureLoggingExtension(ResetPasswordRequestHandler.class);

    @AfterEach
    public void tearDown() {
        assertThat(
                logging.events(),
                not(hasItem(withMessageContaining(SESSION_ID, CommonTestVariables.EMAIL))));
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

        static final String validRequestBody =
                format("{ \"email\": \"%s\"}", CommonTestVariables.EMAIL);
        static NotifyRequest notifyRequest =
                new NotifyRequest(
                        CommonTestVariables.EMAIL,
                        RESET_PASSWORD_WITH_CODE,
                        TEST_SIX_DIGIT_CODE,
                        SupportedLanguage.EN);

        public static APIGatewayProxyRequestEvent validEvent;

        private boolean isSessionWithEmailSent(Session session) {
            return session.getEmailAddress().equals(CommonTestVariables.EMAIL);
        }

        @BeforeEach
        void setup() {
            validEvent = apiRequestEventWithHeadersAndBody(VALID_HEADERS, validRequestBody);
            Subject subject = new Subject("subject_1");
            when(authenticationService.getSubjectFromEmail(CommonTestVariables.EMAIL))
                    .thenReturn(subject);
            when(authenticationService.getPhoneNumber(CommonTestVariables.EMAIL))
                    .thenReturn(Optional.of(CommonTestVariables.UK_MOBILE_NUMBER));
            when(authenticationService.getPhoneNumber(CommonTestVariables.EMAIL))
                    .thenReturn(Optional.of(CommonTestVariables.UK_MOBILE_NUMBER));
            when(authenticationService.getUserProfileByEmailMaybe(CommonTestVariables.EMAIL))
                    .thenReturn(
                            Optional.of(
                                    userProfileWithPhoneNumber(
                                            CommonTestVariables.UK_MOBILE_NUMBER)));
            when(clientSessionService.getClientSessionFromRequestHeaders(any()))
                    .thenReturn(Optional.of(getClientSession()));
            var disabledMfaMethod =
                    new MFAMethod(
                            MFAMethodType.AUTH_APP.getValue(),
                            "first-value",
                            true,
                            false,
                            NowHelper.nowMinus(50, ChronoUnit.DAYS).toString());
            var enabledMfaMethod =
                    new MFAMethod(
                            MFAMethodType.SMS.getValue(),
                            "second-value",
                            true,
                            true,
                            NowHelper.nowMinus(50, ChronoUnit.DAYS).toString());
            when(authenticationService.getUserCredentialsFromEmail(CommonTestVariables.EMAIL))
                    .thenReturn(
                            new UserCredentials()
                                    .withMfaMethods(List.of(disabledMfaMethod, enabledMfaMethod)));
        }

        @Test
        void shouldReturn200WithTheUsersMfaMethodAndSaveOtpCodeForAValidRequest() {
            usingValidSession();
            APIGatewayProxyResponseEvent result = handler.handleRequest(validEvent, context);

            assertEquals(200, result.getStatusCode());
            var expectedBody = "{\"mfaMethodType\":\"SMS\",\"phoneNumberLastThree\":\"890\"}";
            assertEquals(expectedBody, result.getBody());
            verify(codeStorageService)
                    .saveOtpCode(
                            CommonTestVariables.EMAIL,
                            TEST_SIX_DIGIT_CODE,
                            CODE_EXPIRY_TIME,
                            RESET_PASSWORD_WITH_CODE);
            verify(sessionService).storeOrUpdateSession(argThat(this::isSessionWithEmailSent));
        }

        @Test
        void shouldPutMessageOnQueueForAValidCodeFlowRequest() throws Json.JsonException {
            usingValidSession();

            APIGatewayProxyResponseEvent result = handler.handleRequest(validEvent, context);

            assertEquals(200, result.getStatusCode());
            verify(awsSqsClient)
                    .send(
                            argThat(
                                    containsJsonString(
                                            objectMapper.writeValueAsString(notifyRequest))));
        }

        @Test
        void shouldSubmitCorrectAuditEventForAValidRequest() {
            usingValidSession();
            usingValidClientSession();

            handler.handleRequest(validEvent, context);

            verify(auditService)
                    .submitAuditEvent(
                            FrontendAuditableEvent.AUTH_PASSWORD_RESET_REQUESTED,
                            auditContext,
                            PASSWORD_RESET_COUNTER,
                            PASSWORD_RESET_TYPE_FORGOTTEN_PASSWORD);
        }

        @Test
        void checkPasswordResetRequestedAuditEventStillEmittedWhenTICFHeaderNotProvided() {
            usingValidSession();
            var headers = validEvent.getHeaders();
            var headersWithoutTICF =
                    headers.entrySet().stream()
                            .filter(entry -> !entry.getKey().equals(TXMA_AUDIT_ENCODED_HEADER))
                            .collect(
                                    Collectors.toUnmodifiableMap(
                                            Map.Entry::getKey, Map.Entry::getValue));
            validEvent.setHeaders(headersWithoutTICF);

            handler.handleRequest(validEvent, context);

            verify(auditService)
                    .submitAuditEvent(
                            FrontendAuditableEvent.AUTH_PASSWORD_RESET_REQUESTED,
                            auditContext.withTxmaAuditEncoded(Optional.empty()),
                            PASSWORD_RESET_COUNTER,
                            PASSWORD_RESET_TYPE_FORGOTTEN_PASSWORD);
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
            assertThat(result, hasStatus(200));
        }

        @Test
        void shouldReturn200ButNotPutMessageOnQueueIfTestClient() {
            when(configurationService.isTestClientsEnabled()).thenReturn(true);

            usingValidSession();
            usingValidClientSession();
            var result = handler.handleRequest(validEvent, context);

            assertEquals(200, result.getStatusCode());

            verifyNoInteractions(awsSqsClient);
            verify(codeStorageService)
                    .saveOtpCode(
                            CommonTestVariables.EMAIL,
                            TEST_SIX_DIGIT_CODE,
                            CODE_EXPIRY_TIME,
                            RESET_PASSWORD_WITH_CODE);
            verify(sessionService).storeOrUpdateSession(argThat(this::isSessionWithEmailSent));

            verify(auditService)
                    .submitAuditEvent(
                            FrontendAuditableEvent.AUTH_PASSWORD_RESET_REQUESTED_FOR_TEST_CLIENT,
                            auditContext,
                            PASSWORD_RESET_COUNTER,
                            PASSWORD_RESET_TYPE_FORGOTTEN_PASSWORD);
        }

        @Test
        void
                checkPasswordResetRequestedForTestClientAuditEventStillEmittedWhenTICFHeaderNotProvided() {
            when(configurationService.isTestClientsEnabled()).thenReturn(true);
            usingValidSession();
            usingValidClientSession();
            var headers = validEvent.getHeaders();
            var headersWithoutTICF =
                    headers.entrySet().stream()
                            .filter(entry -> !entry.getKey().equals(TXMA_AUDIT_ENCODED_HEADER))
                            .collect(
                                    Collectors.toUnmodifiableMap(
                                            Map.Entry::getKey, Map.Entry::getValue));
            validEvent.setHeaders(headersWithoutTICF);

            var result = handler.handleRequest(validEvent, context);

            assertEquals(200, result.getStatusCode());

            verify(auditService)
                    .submitAuditEvent(
                            FrontendAuditableEvent.AUTH_PASSWORD_RESET_REQUESTED_FOR_TEST_CLIENT,
                            auditContext.withTxmaAuditEncoded(Optional.empty()),
                            PASSWORD_RESET_COUNTER,
                            PASSWORD_RESET_TYPE_FORGOTTEN_PASSWORD);
        }

        @Test
        void shouldReturn404IfUserProfileIsNotFound() {
            when(authenticationService.getUserProfileByEmailMaybe(CommonTestVariables.EMAIL))
                    .thenReturn(Optional.empty());

            usingValidSession();
            var result = handler.handleRequest(validEvent, context);

            assertEquals(404, result.getStatusCode());
            assertThat(result, hasJsonBody(ErrorResponse.ERROR_1056));
        }

        @Test
        public void shouldReturn400IfUserIsBlockedFromRequestingAnyMorePasswordResets() {
            usingSessionWithPasswordResetCount(0);
            var codeRequestType =
                    CodeRequestType.getCodeRequestType(
                            RESET_PASSWORD_WITH_CODE, JourneyType.PASSWORD_RESET);
            var codeRequestBlockedKeyPrefix = CODE_REQUEST_BLOCKED_KEY_PREFIX + codeRequestType;
            when(codeStorageService.isBlockedForEmail(
                            CommonTestVariables.EMAIL, codeRequestBlockedKeyPrefix))
                    .thenReturn(true);

            var result = handler.handleRequest(validEvent, context);

            assertEquals(400, result.getStatusCode());
            assertThat(result, hasJsonBody(ErrorResponse.ERROR_1023));
            verifyNoInteractions(awsSqsClient);
        }

        @Test
        public void shouldReturn400IfUserIsBlockedFromEnteringAnyMoreInvalidPasswordResetsOTPs() {
            usingSessionWithPasswordResetCount(0);
            var codeRequestType =
                    CodeRequestType.getCodeRequestType(
                            RESET_PASSWORD_WITH_CODE, JourneyType.PASSWORD_RESET);
            var codeRequestBlockedKeyPrefix = CODE_BLOCKED_KEY_PREFIX + codeRequestType;
            when(codeStorageService.isBlockedForEmail(
                            CommonTestVariables.EMAIL, codeRequestBlockedKeyPrefix))
                    .thenReturn(true);

            var result = handler.handleRequest(validEvent, context);

            assertEquals(400, result.getStatusCode());
            assertThat(result, hasJsonBody(ErrorResponse.ERROR_1039));
            verifyNoInteractions(awsSqsClient);
        }

        @Test
        public void shouldReturn500IfMessageCannotBeSentToQueue() throws Json.JsonException {
            Mockito.doThrow(SdkClientException.class)
                    .when(awsSqsClient)
                    .send(eq(objectMapper.writeValueAsString(notifyRequest)));

            usingValidSession();
            APIGatewayProxyResponseEvent result = handler.handleRequest(validEvent, context);

            assertEquals(500, result.getStatusCode());
            assertTrue(result.getBody().contains("Error sending message to queue"));
        }

        @Test
        public void shouldReturn400IfUserHasExceededPasswordResetRequestCount() {
            when(configurationService.getLockoutDuration()).thenReturn(LOCKOUT_DURATION);
            var session = usingSessionWithPasswordResetCount(5);

            APIGatewayProxyResponseEvent result = handler.handleRequest(validEvent, context);
            var codeRequestType =
                    CodeRequestType.getCodeRequestType(
                            RESET_PASSWORD_WITH_CODE, JourneyType.PASSWORD_RESET);
            var codeRequestBlockedKeyPrefix = CODE_REQUEST_BLOCKED_KEY_PREFIX + codeRequestType;

            assertEquals(400, result.getStatusCode());
            assertThat(result, hasJsonBody(ErrorResponse.ERROR_1022));
            verify(codeStorageService)
                    .saveBlockedForEmail(
                            CommonTestVariables.EMAIL,
                            codeRequestBlockedKeyPrefix,
                            LOCKOUT_DURATION);
            verify(session).resetPasswordResetCount();
            verifyNoInteractions(awsSqsClient);
        }

        @Test
        void shouldReturn400WhenNoEmailIsPresentInSession() {
            when(authenticationService.getPhoneNumber(CommonTestVariables.EMAIL))
                    .thenReturn(Optional.of(CommonTestVariables.UK_MOBILE_NUMBER));
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
            var body = format("{ \"email\": \"%s\" }", CommonTestVariables.EMAIL);
            APIGatewayProxyRequestEvent event = apiRequestEventWithHeadersAndBody(Map.of(), body);
            APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

            assertEquals(400, result.getStatusCode());

            verify(awsSqsClient, never()).send(anyString());
            verify(codeStorageService, never())
                    .saveOtpCode(anyString(), anyString(), anyLong(), any(NotificationType.class));
            verify(sessionService, never()).storeOrUpdateSession(any());
            verifyNoInteractions(awsSqsClient);
        }

        @Test
        public void shouldReturn400IfRequestIsMissingEmail() {
            usingValidSession();
            var body = "{ }";
            APIGatewayProxyRequestEvent event =
                    apiRequestEventWithHeadersAndBody(VALID_HEADERS, body);
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

    private Session usingSessionWithPasswordResetCount(int passwordResetCount) {
        Session session = mock(Session.class);
        when(session.getEmailAddress()).thenReturn(CommonTestVariables.EMAIL);
        when(session.getSessionId()).thenReturn(SESSION_ID);
        when(session.validateSession(CommonTestVariables.EMAIL)).thenReturn(true);
        when(session.getPasswordResetCount()).thenReturn(passwordResetCount);
        when(sessionService.getSessionFromRequestHeaders(anyMap()))
                .thenReturn(Optional.of(session));
        return session;
    }

    private UserProfile userProfileWithPhoneNumber(String phoneNumber) {
        return new UserProfile().withEmail(CommonTestVariables.EMAIL).withPhoneNumber(phoneNumber);
    }

    private ClientSession getClientSession() {
        ResponseType responseType = new ResponseType(ResponseType.Value.CODE);
        Scope scope = new Scope();
        scope.add(OIDCScopeValue.OPENID);
        AuthenticationRequest authRequest =
                new AuthenticationRequest.Builder(
                                responseType,
                                scope,
                                new ClientID(CLIENT_ID),
                                URI.create("http://localhost/redirect"))
                        .build();

        return new ClientSession(
                authRequest.toParameters(), null, mock(VectorOfTrust.class), CLIENT_NAME);
    }
}
