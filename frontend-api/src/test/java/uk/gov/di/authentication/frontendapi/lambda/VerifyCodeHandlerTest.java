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
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.mockito.ArgumentMatcher;
import uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.ClientSession;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.SessionService;
import uk.gov.di.authentication.shared.services.ValidationService;
import uk.gov.di.authentication.shared.state.UserContext;
import uk.gov.di.authentication.sharedtest.logging.CaptureLoggingExtension;

import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.not;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.shared.entity.CredentialTrustLevel.MEDIUM_LEVEL;
import static uk.gov.di.authentication.shared.entity.NotificationType.MFA_SMS;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_EMAIL;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_PHONE_NUMBER;
import static uk.gov.di.authentication.shared.services.AuditService.MetadataPair.pair;
import static uk.gov.di.authentication.shared.services.CodeStorageService.CODE_BLOCKED_KEY_PREFIX;
import static uk.gov.di.authentication.sharedtest.helper.RequestEventHelper.contextWithSourceIp;
import static uk.gov.di.authentication.sharedtest.logging.LogEventMatcher.withMessageContaining;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class VerifyCodeHandlerTest {

    private static final String TEST_EMAIL_ADDRESS = "test@test.com";
    private static final String CODE = "123456";
    private static final String CLIENT_ID = "client-id";
    private static final String TEST_CLIENT_ID = "test-client-id";
    private static final String TEST_CLIENT_CODE = "654321";
    private static final String TEST_CLIENT_EMAIL =
            "testclient.user1@digital.cabinet-office.gov.uk";
    private static final long CODE_EXPIRY_TIME = 900;
    private static final long BLOCKED_EMAIL_DURATION = 799;

    private static final URI REDIRECT_URI = URI.create("http://localhost/redirect");
    private final Context context = mock(Context.class);
    private final SessionService sessionService = mock(SessionService.class);
    private final CodeStorageService codeStorageService = mock(CodeStorageService.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final ValidationService validationService = mock(ValidationService.class);
    private final UserProfile userProfile = mock(UserProfile.class);
    private final Session session = new Session("session-id").setEmailAddress(TEST_EMAIL_ADDRESS);
    private final Session testClientSession =
            new Session("test-client-session-id").setEmailAddress(TEST_CLIENT_EMAIL);
    private final ClientSessionService clientSessionService = mock(ClientSessionService.class);
    private final ClientService clientService = mock(ClientService.class);
    private final AuthenticationService authenticationService = mock(AuthenticationService.class);
    private final ClientSession clientSession = mock(ClientSession.class);
    private final AuditService auditService = mock(AuditService.class);
    private final CloudwatchMetricsService cloudwatchMetricsService =
            mock(CloudwatchMetricsService.class);

    private final ClientRegistry clientRegistry =
            new ClientRegistry().setTestClient(false).setClientID(CLIENT_ID);
    private final ClientRegistry testClientRegistry =
            new ClientRegistry()
                    .setTestClient(true)
                    .setClientID(TEST_CLIENT_ID)
                    .setTestClientEmailAllowlist(
                            List.of("testclient.user1@digital.cabinet-office.gov.uk"));

    private VerifyCodeHandler handler;

    @RegisterExtension
    private final CaptureLoggingExtension logging =
            new CaptureLoggingExtension(VerifyCodeHandler.class);

    @AfterEach
    void tearDown() {
        assertThat(
                logging.events(),
                not(
                        hasItem(
                                withMessageContaining(
                                        CLIENT_ID,
                                        TEST_CLIENT_CODE,
                                        session.getSessionId(),
                                        testClientSession.getSessionId()))));
    }

    @BeforeEach
    void setup() {
        handler =
                new VerifyCodeHandler(
                        configurationService,
                        sessionService,
                        clientSessionService,
                        clientService,
                        authenticationService,
                        codeStorageService,
                        validationService,
                        auditService,
                        cloudwatchMetricsService);

        when(authenticationService.getUserProfileFromEmail(TEST_EMAIL_ADDRESS))
                .thenReturn(Optional.of(userProfile));

        when(authenticationService.getUserProfileFromEmail(TEST_CLIENT_EMAIL))
                .thenReturn(Optional.of(userProfile));

        when(userProfile.getSubjectID()).thenReturn("test-subject-id");

        when(configurationService.getEnvironment()).thenReturn("unit-test");
    }

    private ArgumentMatcher<UserContext> isContextWithUserProfile(UserProfile userProfile) {
        return userContext -> userContext.getUserProfile().filter(userProfile::equals).isPresent();
    }

    @Test
    void shouldReturn204ForValidVerifyEmailRequest() {
        when(configurationService.getCodeMaxRetries()).thenReturn(5);
        when(codeStorageService.getOtpCode(TEST_EMAIL_ADDRESS, VERIFY_EMAIL))
                .thenReturn(Optional.of(CODE));
        when(validationService.validateVerificationCode(
                        eq(VERIFY_EMAIL),
                        eq(Optional.of(CODE)),
                        eq(CODE),
                        any(Session.class),
                        eq(5)))
                .thenReturn(Optional.empty());
        APIGatewayProxyResponseEvent result = makeCallWithCode(CODE, VERIFY_EMAIL.toString());

        verify(codeStorageService).deleteOtpCode(TEST_EMAIL_ADDRESS, VERIFY_EMAIL);
        assertThat(result, hasStatus(204));

        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.CODE_VERIFIED,
                        context.getAwsRequestId(),
                        session.getSessionId(),
                        CLIENT_ID,
                        "test-subject-id",
                        TEST_EMAIL_ADDRESS,
                        "123.123.123.123",
                        AuditService.UNKNOWN,
                        PersistentIdHelper.PERSISTENT_ID_UNKNOWN_VALUE,
                        pair("notification-type", VERIFY_EMAIL.name()));
    }

    @Test
    void shouldReturn204ForValidVerifyPhoneNumberRequest() {
        when(configurationService.getCodeMaxRetries()).thenReturn(5);

        when(validationService.validateVerificationCode(
                        eq(VERIFY_PHONE_NUMBER),
                        eq(Optional.of(CODE)),
                        eq(CODE),
                        any(Session.class),
                        eq(5)))
                .thenReturn(Optional.empty());
        when(codeStorageService.getOtpCode(TEST_EMAIL_ADDRESS, VERIFY_PHONE_NUMBER))
                .thenReturn(Optional.of(CODE));

        APIGatewayProxyResponseEvent result =
                makeCallWithCode(CODE, VERIFY_PHONE_NUMBER.toString());

        verify(codeStorageService).deleteOtpCode(TEST_EMAIL_ADDRESS, VERIFY_PHONE_NUMBER);
        verify(authenticationService).updatePhoneNumberVerifiedStatus(TEST_EMAIL_ADDRESS, true);
        assertThat(result, hasStatus(204));
        assertThat(session.getCurrentCredentialStrength(), equalTo(MEDIUM_LEVEL));

        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.CODE_VERIFIED,
                        context.getAwsRequestId(),
                        session.getSessionId(),
                        CLIENT_ID,
                        "test-subject-id",
                        TEST_EMAIL_ADDRESS,
                        "123.123.123.123",
                        AuditService.UNKNOWN,
                        PersistentIdHelper.PERSISTENT_ID_UNKNOWN_VALUE,
                        pair("notification-type", VERIFY_PHONE_NUMBER.name()));

        verify(cloudwatchMetricsService)
                .incrementCounter(
                        "NewAccount", Map.of("Environment", "unit-test", "Client", "client-id"));
    }

    @Test
    void shouldReturnEmailCodeNotValidStateIfRequestCodeDoesNotMatchStoredCode() {
        when(configurationService.getCodeMaxRetries()).thenReturn(5);
        when(codeStorageService.getOtpCode(TEST_EMAIL_ADDRESS, VERIFY_EMAIL))
                .thenReturn(Optional.of(CODE));
        when(validationService.validateVerificationCode(
                        eq(VERIFY_EMAIL),
                        eq(Optional.of(CODE)),
                        eq("123457"),
                        any(Session.class),
                        eq(5)))
                .thenReturn(Optional.of(ErrorResponse.ERROR_1036));

        APIGatewayProxyResponseEvent result = makeCallWithCode("123457", VERIFY_EMAIL.toString());

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1036));
    }

    @Test
    void shouldReturnPhoneNumberCodeNotValidStateIfRequestCodeDoesNotMatchStoredCode() {
        when(configurationService.getCodeMaxRetries()).thenReturn(5);

        when(validationService.validateVerificationCode(
                        eq(VERIFY_PHONE_NUMBER),
                        eq(Optional.of(CODE)),
                        eq(CODE),
                        any(Session.class),
                        eq(5)))
                .thenReturn(Optional.of(ErrorResponse.ERROR_1037));
        when(codeStorageService.getOtpCode(TEST_EMAIL_ADDRESS, VERIFY_PHONE_NUMBER))
                .thenReturn(Optional.of(CODE));

        APIGatewayProxyResponseEvent result =
                makeCallWithCode(CODE, VERIFY_PHONE_NUMBER.toString());

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1037));
        verify(authenticationService, never())
                .updatePhoneNumberVerifiedStatus(TEST_EMAIL_ADDRESS, true);
    }

    @Test
    void shouldReturn400IfRequestIsMissingNotificationType() {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("Session-Id", "a-session-id"));
        event.setBody(format("{ \"code\": \"%s\"}", CODE));
        when(sessionService.getSessionFromRequestHeaders(event.getHeaders()))
                .thenReturn(Optional.of(session));

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);
        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1001));
    }

    @Test
    void shouldReturn400IfSessionIdIsInvalid() {
        APIGatewayProxyResponseEvent result =
                makeCallWithCode("123456", VERIFY_EMAIL.toString(), Optional.empty(), CLIENT_ID);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1000));
    }

    @Test
    void shouldReturn400IfNotificationTypeIsNotValid() {
        APIGatewayProxyResponseEvent result = makeCallWithCode(CODE, "VERIFY_TEXT");

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1001));
    }

    @Test
    void shouldUpdateRedisWhenUserHasReachedMaxPhoneNumberCodeAttempts() {
        final String USER_INPUT = "123456";
        when(configurationService.getCodeMaxRetries()).thenReturn(5);
        when(configurationService.getCodeExpiry()).thenReturn(CODE_EXPIRY_TIME);
        when(configurationService.getBlockedEmailDuration()).thenReturn(BLOCKED_EMAIL_DURATION);

        when(validationService.validateVerificationCode(
                        eq(VERIFY_PHONE_NUMBER),
                        eq(Optional.of(CODE)),
                        eq(USER_INPUT),
                        any(Session.class),
                        eq(5)))
                .thenReturn(Optional.of(ErrorResponse.ERROR_1034));
        when(codeStorageService.getOtpCode(TEST_EMAIL_ADDRESS, VERIFY_PHONE_NUMBER))
                .thenReturn(Optional.of(CODE));

        APIGatewayProxyResponseEvent result =
                makeCallWithCode(USER_INPUT, VERIFY_PHONE_NUMBER.toString());

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1034));
        assertThat(session.getRetryCount(), equalTo(0));
        verify(authenticationService, never())
                .updatePhoneNumberVerifiedStatus(TEST_EMAIL_ADDRESS, true);
        verify(codeStorageService)
                .saveBlockedForEmail(
                        TEST_EMAIL_ADDRESS, CODE_BLOCKED_KEY_PREFIX, BLOCKED_EMAIL_DURATION);
        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.CODE_MAX_RETRIES_REACHED,
                        context.getAwsRequestId(),
                        session.getSessionId(),
                        CLIENT_ID,
                        "test-subject-id",
                        TEST_EMAIL_ADDRESS,
                        "123.123.123.123",
                        AuditService.UNKNOWN,
                        PersistentIdHelper.PERSISTENT_ID_UNKNOWN_VALUE,
                        pair("notification-type", VERIFY_PHONE_NUMBER.name()));
    }

    @Test
    void shouldReturnMaxReachedWhenPhoneNumberCodeIsBlocked() {
        final String USER_INPUT = "123456";
        when(codeStorageService.isBlockedForEmail(TEST_EMAIL_ADDRESS, CODE_BLOCKED_KEY_PREFIX))
                .thenReturn(true);

        APIGatewayProxyResponseEvent result =
                makeCallWithCode(USER_INPUT, VERIFY_PHONE_NUMBER.toString());

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1034));
        verify(codeStorageService, never())
                .getOtpCode(session.getEmailAddress(), VERIFY_PHONE_NUMBER);
    }

    @Test
    void shouldUpdateRedisWhenUserHasReachedMaxEmailCodeAttempts() {

        final String USER_INPUT = "123456";
        when(configurationService.getCodeMaxRetries()).thenReturn(5);
        when(configurationService.getCodeExpiry()).thenReturn(CODE_EXPIRY_TIME);
        when(configurationService.getBlockedEmailDuration()).thenReturn(BLOCKED_EMAIL_DURATION);
        when(validationService.validateVerificationCode(
                        eq(VERIFY_EMAIL),
                        eq(Optional.of(CODE)),
                        eq(USER_INPUT),
                        any(Session.class),
                        eq(5)))
                .thenReturn(Optional.of(ErrorResponse.ERROR_1033));
        when(codeStorageService.getOtpCode(TEST_EMAIL_ADDRESS, VERIFY_EMAIL))
                .thenReturn(Optional.of(CODE));

        APIGatewayProxyResponseEvent result = makeCallWithCode(USER_INPUT, VERIFY_EMAIL.toString());

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1033));
        assertThat(session.getRetryCount(), equalTo(0));
        verify(codeStorageService)
                .saveBlockedForEmail(
                        TEST_EMAIL_ADDRESS, CODE_BLOCKED_KEY_PREFIX, BLOCKED_EMAIL_DURATION);
        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.CODE_MAX_RETRIES_REACHED,
                        context.getAwsRequestId(),
                        session.getSessionId(),
                        CLIENT_ID,
                        "test-subject-id",
                        TEST_EMAIL_ADDRESS,
                        "123.123.123.123",
                        AuditService.UNKNOWN,
                        PersistentIdHelper.PERSISTENT_ID_UNKNOWN_VALUE,
                        pair("notification-type", VERIFY_EMAIL.name()));
    }

    @Test
    void shouldReturnMaxReachedWhenEmailCodeIsBlocked() {
        final String USER_INPUT = "123456";
        when(codeStorageService.isBlockedForEmail(TEST_EMAIL_ADDRESS, CODE_BLOCKED_KEY_PREFIX))
                .thenReturn(true);

        APIGatewayProxyResponseEvent result = makeCallWithCode(USER_INPUT, VERIFY_EMAIL.toString());

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1033));
    }

    @Test
    void shouldReturn204ForValidMfaSmsRequest() {
        when(configurationService.getCodeMaxRetries()).thenReturn(5);
        when(codeStorageService.getOtpCode(TEST_EMAIL_ADDRESS, MFA_SMS))
                .thenReturn(Optional.of(CODE));
        when(validationService.validateVerificationCode(
                        eq(MFA_SMS), eq(Optional.of(CODE)), eq(CODE), any(Session.class), eq(5)))
                .thenReturn(Optional.empty());

        APIGatewayProxyResponseEvent result = makeCallWithCode(CODE, MFA_SMS.toString());

        verify(codeStorageService).deleteOtpCode(TEST_EMAIL_ADDRESS, MFA_SMS);
        assertThat(result, hasStatus(204));

        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.CODE_VERIFIED,
                        context.getAwsRequestId(),
                        session.getSessionId(),
                        CLIENT_ID,
                        "test-subject-id",
                        TEST_EMAIL_ADDRESS,
                        "123.123.123.123",
                        AuditService.UNKNOWN,
                        PersistentIdHelper.PERSISTENT_ID_UNKNOWN_VALUE,
                        pair("notification-type", MFA_SMS.name()));
    }

    @Test
    void shouldReturnMfaCodeNotValidStateIfRequestCodeDoesNotMatchStoredCode() {
        when(configurationService.getCodeMaxRetries()).thenReturn(5);
        when(codeStorageService.getOtpCode(TEST_EMAIL_ADDRESS, MFA_SMS))
                .thenReturn(Optional.of(CODE));
        when(validationService.validateVerificationCode(
                        eq(MFA_SMS),
                        eq(Optional.of(CODE)),
                        eq("123457"),
                        any(Session.class),
                        eq(5)))
                .thenReturn(Optional.of(ErrorResponse.ERROR_1035));

        APIGatewayProxyResponseEvent result = makeCallWithCode("123457", MFA_SMS.toString());

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1035));
    }

    @Test
    void shouldUpdateRedisWhenUserHasReachedMaxMfaCodeAttempts() {
        final String USER_INPUT = "123456";
        when(configurationService.getCodeMaxRetries()).thenReturn(5);
        when(configurationService.getCodeExpiry()).thenReturn(CODE_EXPIRY_TIME);
        when(configurationService.getBlockedEmailDuration()).thenReturn(BLOCKED_EMAIL_DURATION);
        when(validationService.validateVerificationCode(
                        eq(MFA_SMS),
                        eq(Optional.of(CODE)),
                        eq(USER_INPUT),
                        any(Session.class),
                        eq(5)))
                .thenReturn(Optional.of(ErrorResponse.ERROR_1027));
        when(codeStorageService.getOtpCode(TEST_EMAIL_ADDRESS, MFA_SMS))
                .thenReturn(Optional.of(CODE));

        APIGatewayProxyResponseEvent result = makeCallWithCode(USER_INPUT, MFA_SMS.toString());

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1027));
        assertThat(session.getRetryCount(), equalTo(0));
        verify(codeStorageService)
                .saveBlockedForEmail(
                        TEST_EMAIL_ADDRESS, CODE_BLOCKED_KEY_PREFIX, BLOCKED_EMAIL_DURATION);
        verify(auditService)
                .submitAuditEvent(
                        FrontendAuditableEvent.CODE_MAX_RETRIES_REACHED,
                        context.getAwsRequestId(),
                        session.getSessionId(),
                        CLIENT_ID,
                        "test-subject-id",
                        TEST_EMAIL_ADDRESS,
                        "123.123.123.123",
                        AuditService.UNKNOWN,
                        PersistentIdHelper.PERSISTENT_ID_UNKNOWN_VALUE,
                        pair("notification-type", MFA_SMS.name()));
    }

    @Test
    void shouldReturnMaxReachedWhenMfaCodeIsBlocked() {
        final String USER_INPUT = "123456";
        when(codeStorageService.isBlockedForEmail(TEST_EMAIL_ADDRESS, CODE_BLOCKED_KEY_PREFIX))
                .thenReturn(true);

        APIGatewayProxyResponseEvent result = makeCallWithCode(USER_INPUT, MFA_SMS.toString());

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1027));

        verify(codeStorageService, never()).getOtpCode(session.getEmailAddress(), MFA_SMS);
    }

    @Test
    void shouldReturn204ForValidVerifyEmailRequestUsingTestClient() {
        when(configurationService.isTestClientsEnabled()).thenReturn(true);
        when(configurationService.getCodeMaxRetries()).thenReturn(5);
        when(configurationService.getTestClientVerifyEmailOTP())
                .thenReturn(Optional.of(TEST_CLIENT_CODE));
        when(codeStorageService.getOtpCode(TEST_CLIENT_EMAIL, VERIFY_EMAIL))
                .thenReturn(Optional.of(CODE));
        when(validationService.validateVerificationCode(
                        eq(VERIFY_EMAIL),
                        eq(Optional.of(TEST_CLIENT_CODE)),
                        eq(TEST_CLIENT_CODE),
                        any(Session.class),
                        eq(5)))
                .thenReturn(Optional.empty());
        APIGatewayProxyResponseEvent result =
                makeCallWithCode(
                        TEST_CLIENT_CODE,
                        VERIFY_EMAIL.toString(),
                        Optional.of(testClientSession),
                        TEST_CLIENT_ID);

        verify(codeStorageService).deleteOtpCode(TEST_CLIENT_EMAIL, VERIFY_EMAIL);
        assertThat(result, hasStatus(204));
    }

    private APIGatewayProxyResponseEvent makeCallWithCode(String code, String notificationType) {
        return makeCallWithCode(code, notificationType, Optional.of(session), CLIENT_ID);
    }

    private APIGatewayProxyResponseEvent makeCallWithCode(
            String code, String notificationType, Optional<Session> session, String clientId) {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setRequestContext(contextWithSourceIp("123.123.123.123"));
        event.setHeaders(
                Map.of(
                        "Session-Id",
                        session.map(Session::getSessionId).orElse("invalid-session-id"),
                        "Client-Session-Id",
                        "client-session-id"));
        event.setBody(
                format(
                        "{ \"code\": \"%s\", \"notificationType\": \"%s\" }",
                        code, notificationType));
        when(sessionService.getSessionFromRequestHeaders(event.getHeaders())).thenReturn(session);
        when(clientSessionService.getClientSessionFromRequestHeaders(event.getHeaders()))
                .thenReturn(Optional.of(clientSession));
        when(clientSession.getAuthRequestParams())
                .thenReturn(withAuthenticationRequest(clientId).toParameters());
        when(clientService.getClient(CLIENT_ID)).thenReturn(Optional.of(clientRegistry));
        when(clientService.getClient(TEST_CLIENT_ID)).thenReturn(Optional.of(testClientRegistry));
        when(clientSessionService.getClientSessionFromRequestHeaders(event.getHeaders()))
                .thenReturn(Optional.of(clientSession));
        return handler.handleRequest(event, context);
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
