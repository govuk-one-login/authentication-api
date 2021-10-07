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
import org.mockito.ArgumentMatcher;
import uk.gov.di.authentication.shared.entity.BaseAPIResponse;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.ClientSession;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.SessionAction;
import uk.gov.di.authentication.shared.entity.SessionState;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ClientService;
import uk.gov.di.authentication.shared.services.ClientSessionService;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.SessionService;
import uk.gov.di.authentication.shared.services.ValidationService;
import uk.gov.di.authentication.shared.state.StateMachine;
import uk.gov.di.authentication.shared.state.UserContext;

import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.shared.entity.CredentialTrustLevel.MEDIUM_LEVEL;
import static uk.gov.di.authentication.shared.entity.NotificationType.MFA_SMS;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_EMAIL;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_PHONE_NUMBER;
import static uk.gov.di.authentication.shared.entity.SessionAction.USER_ENTERED_INVALID_EMAIL_VERIFICATION_CODE;
import static uk.gov.di.authentication.shared.entity.SessionAction.USER_ENTERED_INVALID_EMAIL_VERIFICATION_CODE_TOO_MANY_TIMES;
import static uk.gov.di.authentication.shared.entity.SessionAction.USER_ENTERED_INVALID_MFA_CODE;
import static uk.gov.di.authentication.shared.entity.SessionAction.USER_ENTERED_INVALID_MFA_CODE_TOO_MANY_TIMES;
import static uk.gov.di.authentication.shared.entity.SessionAction.USER_ENTERED_INVALID_PHONE_VERIFICATION_CODE;
import static uk.gov.di.authentication.shared.entity.SessionAction.USER_ENTERED_INVALID_PHONE_VERIFICATION_CODE_TOO_MANY_TIMES;
import static uk.gov.di.authentication.shared.entity.SessionAction.USER_ENTERED_VALID_EMAIL_VERIFICATION_CODE;
import static uk.gov.di.authentication.shared.entity.SessionAction.USER_ENTERED_VALID_MFA_CODE;
import static uk.gov.di.authentication.shared.entity.SessionAction.USER_ENTERED_VALID_PHONE_VERIFICATION_CODE;
import static uk.gov.di.authentication.shared.entity.SessionState.EMAIL_CODE_MAX_RETRIES_REACHED;
import static uk.gov.di.authentication.shared.entity.SessionState.EMAIL_CODE_NOT_VALID;
import static uk.gov.di.authentication.shared.entity.SessionState.EMAIL_CODE_VERIFIED;
import static uk.gov.di.authentication.shared.entity.SessionState.MFA_CODE_MAX_RETRIES_REACHED;
import static uk.gov.di.authentication.shared.entity.SessionState.MFA_CODE_NOT_VALID;
import static uk.gov.di.authentication.shared.entity.SessionState.MFA_CODE_VERIFIED;
import static uk.gov.di.authentication.shared.entity.SessionState.MFA_SMS_CODE_SENT;
import static uk.gov.di.authentication.shared.entity.SessionState.NEW;
import static uk.gov.di.authentication.shared.entity.SessionState.PHONE_NUMBER_CODE_MAX_RETRIES_REACHED;
import static uk.gov.di.authentication.shared.entity.SessionState.PHONE_NUMBER_CODE_NOT_VALID;
import static uk.gov.di.authentication.shared.entity.SessionState.PHONE_NUMBER_CODE_VERIFIED;
import static uk.gov.di.authentication.shared.entity.SessionState.UPDATED_TERMS_AND_CONDITIONS;
import static uk.gov.di.authentication.shared.entity.SessionState.VERIFY_EMAIL_CODE_SENT;
import static uk.gov.di.authentication.shared.entity.SessionState.VERIFY_PHONE_NUMBER_CODE_SENT;
import static uk.gov.di.authentication.shared.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.authentication.shared.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class VerifyCodeRequestHandlerTest {

    private static final String TEST_EMAIL_ADDRESS = "test@test.com";
    private static final String CODE = "123456";
    private static final String CLIENT_ID = "client-id";
    private static final String TEST_CLIENT_ID = "test-client-id";
    private static final String TEST_CLIENT_CODE = "654321";
    private static final String TEST_CLIENT_EMAIL =
            "testclient.user1@digital.cabinet-office.gov.uk";

    private static final URI REDIRECT_URI = URI.create("http://localhost/redirect");
    private final Context context = mock(Context.class);
    private final SessionService sessionService = mock(SessionService.class);
    private final CodeStorageService codeStorageService = mock(CodeStorageService.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final ValidationService validationService = mock(ValidationService.class);
    private final StateMachine<SessionState, SessionAction, UserContext> stateMachine =
            mock(StateMachine.class);
    private final UserProfile userProfile = mock(UserProfile.class);
    private final Session session =
            new Session("session-id")
                    .setEmailAddress(TEST_EMAIL_ADDRESS)
                    .setState(VERIFY_EMAIL_CODE_SENT);
    private final Session testClientSession =
            new Session("test-client-session-id")
                    .setEmailAddress(TEST_CLIENT_EMAIL)
                    .setState(VERIFY_EMAIL_CODE_SENT);
    private final ClientSessionService clientSessionService = mock(ClientSessionService.class);
    private final ClientService clientService = mock(ClientService.class);
    private final AuthenticationService authenticationService = mock(AuthenticationService.class);
    private final ClientSession clientSession = mock(ClientSession.class);
    private final ClientRegistry clientRegistry =
            new ClientRegistry().setTestClient(false).setClientID(CLIENT_ID);
    private final ClientRegistry testClientRegistry =
            new ClientRegistry()
                    .setTestClient(true)
                    .setClientID(TEST_CLIENT_ID)
                    .setTestClientEmailAllowlist(
                            List.of("testclient.user1@digital.cabinet-office.gov.uk"));

    private VerifyCodeHandler handler;

    @BeforeEach
    public void setup() {
        handler =
                new VerifyCodeHandler(
                        configurationService,
                        sessionService,
                        clientSessionService,
                        clientService,
                        authenticationService,
                        codeStorageService,
                        validationService,
                        stateMachine);

        when(authenticationService.getUserProfileFromEmail(eq(TEST_EMAIL_ADDRESS)))
                .thenReturn(Optional.of(userProfile));

        when(authenticationService.getUserProfileFromEmail(eq(TEST_CLIENT_EMAIL)))
                .thenReturn(Optional.of(userProfile));

        when(stateMachine.transition(
                        eq(VERIFY_EMAIL_CODE_SENT),
                        eq(USER_ENTERED_VALID_EMAIL_VERIFICATION_CODE),
                        argThat(isContextWithUserProfile(userProfile))))
                .thenReturn(EMAIL_CODE_VERIFIED);
        when(stateMachine.transition(
                        eq(VERIFY_EMAIL_CODE_SENT),
                        eq(USER_ENTERED_INVALID_EMAIL_VERIFICATION_CODE),
                        argThat(isContextWithUserProfile(userProfile))))
                .thenReturn(EMAIL_CODE_NOT_VALID);
        when(stateMachine.transition(
                        eq(EMAIL_CODE_NOT_VALID),
                        eq(USER_ENTERED_INVALID_EMAIL_VERIFICATION_CODE_TOO_MANY_TIMES),
                        argThat(isContextWithUserProfile(userProfile))))
                .thenReturn(EMAIL_CODE_MAX_RETRIES_REACHED);

        when(stateMachine.transition(
                        eq(VERIFY_PHONE_NUMBER_CODE_SENT),
                        eq(USER_ENTERED_VALID_PHONE_VERIFICATION_CODE),
                        argThat(isContextWithUserProfile(userProfile))))
                .thenReturn(PHONE_NUMBER_CODE_VERIFIED);
        when(stateMachine.transition(
                        eq(VERIFY_PHONE_NUMBER_CODE_SENT),
                        eq(USER_ENTERED_INVALID_PHONE_VERIFICATION_CODE),
                        argThat(isContextWithUserProfile(userProfile))))
                .thenReturn(PHONE_NUMBER_CODE_NOT_VALID);
        when(stateMachine.transition(
                        eq(PHONE_NUMBER_CODE_NOT_VALID),
                        eq(USER_ENTERED_INVALID_PHONE_VERIFICATION_CODE_TOO_MANY_TIMES),
                        argThat(isContextWithUserProfile(userProfile))))
                .thenReturn(PHONE_NUMBER_CODE_MAX_RETRIES_REACHED);

        when(stateMachine.transition(
                        eq(MFA_SMS_CODE_SENT),
                        eq(USER_ENTERED_INVALID_MFA_CODE),
                        argThat(isContextWithUserProfile(userProfile))))
                .thenReturn(MFA_CODE_NOT_VALID);
        when(stateMachine.transition(
                        eq(MFA_CODE_NOT_VALID),
                        eq(USER_ENTERED_VALID_MFA_CODE),
                        argThat(isContextWithUserProfile(userProfile))))
                .thenReturn(MFA_CODE_VERIFIED);
        when(stateMachine.transition(
                        eq(MFA_CODE_NOT_VALID),
                        eq(USER_ENTERED_INVALID_MFA_CODE),
                        argThat(isContextWithUserProfile(userProfile))))
                .thenReturn(MFA_CODE_NOT_VALID);
        when(stateMachine.transition(
                        eq(MFA_CODE_NOT_VALID),
                        eq(USER_ENTERED_INVALID_MFA_CODE_TOO_MANY_TIMES),
                        argThat(isContextWithUserProfile(userProfile))))
                .thenReturn(MFA_CODE_MAX_RETRIES_REACHED);
    }

    private ArgumentMatcher<UserContext> isContextWithUserProfile(UserProfile userProfile) {
        return userContext -> userContext.getUserProfile().filter(userProfile::equals).isPresent();
    }

    @Test
    public void shouldReturn200ForValidVerifyEmailRequest() throws JsonProcessingException {
        when(configurationService.getCodeMaxRetries()).thenReturn(5);
        when(codeStorageService.getOtpCode(TEST_EMAIL_ADDRESS, VERIFY_EMAIL))
                .thenReturn(Optional.of(CODE));
        when(validationService.validateVerificationCode(
                        eq(VERIFY_EMAIL),
                        eq(Optional.of(CODE)),
                        eq(CODE),
                        any(Session.class),
                        eq(5)))
                .thenReturn(USER_ENTERED_VALID_EMAIL_VERIFICATION_CODE);
        APIGatewayProxyResponseEvent result = makeCallWithCode(CODE, VERIFY_EMAIL.toString());

        verify(codeStorageService).deleteOtpCode(TEST_EMAIL_ADDRESS, VERIFY_EMAIL);
        assertThat(result, hasStatus(200));
        BaseAPIResponse codeResponse =
                new ObjectMapper().readValue(result.getBody(), BaseAPIResponse.class);
        assertThat(codeResponse.getSessionState(), equalTo(EMAIL_CODE_VERIFIED));
    }

    @Test
    public void shouldReturn200ForValidVerifyPhoneNumberRequest() throws JsonProcessingException {
        session.setState(VERIFY_PHONE_NUMBER_CODE_SENT);
        when(configurationService.getCodeMaxRetries()).thenReturn(5);

        when(validationService.validateVerificationCode(
                        eq(VERIFY_PHONE_NUMBER),
                        eq(Optional.of(CODE)),
                        eq(CODE),
                        any(Session.class),
                        eq(5)))
                .thenReturn(USER_ENTERED_VALID_PHONE_VERIFICATION_CODE);
        when(codeStorageService.getOtpCode(TEST_EMAIL_ADDRESS, VERIFY_PHONE_NUMBER))
                .thenReturn(Optional.of(CODE));

        APIGatewayProxyResponseEvent result =
                makeCallWithCode(CODE, VERIFY_PHONE_NUMBER.toString());

        verify(codeStorageService).deleteOtpCode(TEST_EMAIL_ADDRESS, VERIFY_PHONE_NUMBER);
        verify(authenticationService).updatePhoneNumberVerifiedStatus(TEST_EMAIL_ADDRESS, true);
        assertThat(result, hasStatus(200));
        BaseAPIResponse codeResponse =
                new ObjectMapper().readValue(result.getBody(), BaseAPIResponse.class);
        assertThat(codeResponse.getSessionState(), equalTo(PHONE_NUMBER_CODE_VERIFIED));
        assertThat(session.getCurrentCredentialStrength(), equalTo(MEDIUM_LEVEL));
    }

    @Test
    public void shouldReturnEmailCodeNotValidStateIfRequestCodeDoesNotMatchStoredCode()
            throws JsonProcessingException {
        when(configurationService.getCodeMaxRetries()).thenReturn(5);
        when(codeStorageService.getOtpCode(TEST_EMAIL_ADDRESS, VERIFY_EMAIL))
                .thenReturn(Optional.of(CODE));
        when(validationService.validateVerificationCode(
                        eq(VERIFY_EMAIL),
                        eq(Optional.of(CODE)),
                        eq("123457"),
                        any(Session.class),
                        eq(5)))
                .thenReturn(USER_ENTERED_INVALID_EMAIL_VERIFICATION_CODE);

        APIGatewayProxyResponseEvent result = makeCallWithCode("123457", VERIFY_EMAIL.toString());

        BaseAPIResponse codeResponse =
                new ObjectMapper().readValue(result.getBody(), BaseAPIResponse.class);
        assertThat(result, hasStatus(400));
        assertThat(codeResponse.getSessionState(), equalTo(EMAIL_CODE_NOT_VALID));
    }

    @Test
    public void shouldReturnPhoneNumberCodeNotValidStateIfRequestCodeDoesNotMatchStoredCode()
            throws JsonProcessingException {
        session.setState(VERIFY_PHONE_NUMBER_CODE_SENT);
        when(configurationService.getCodeMaxRetries()).thenReturn(5);

        when(validationService.validateVerificationCode(
                        eq(VERIFY_PHONE_NUMBER),
                        eq(Optional.of(CODE)),
                        eq(CODE),
                        any(Session.class),
                        eq(5)))
                .thenReturn(USER_ENTERED_INVALID_PHONE_VERIFICATION_CODE);
        when(codeStorageService.getOtpCode(TEST_EMAIL_ADDRESS, VERIFY_PHONE_NUMBER))
                .thenReturn(Optional.of(CODE));

        APIGatewayProxyResponseEvent result =
                makeCallWithCode(CODE, VERIFY_PHONE_NUMBER.toString());

        BaseAPIResponse codeResponse =
                new ObjectMapper().readValue(result.getBody(), BaseAPIResponse.class);
        assertThat(result, hasStatus(400));
        assertThat(codeResponse.getSessionState(), equalTo(PHONE_NUMBER_CODE_NOT_VALID));
        verify(authenticationService, never())
                .updatePhoneNumberVerifiedStatus(TEST_EMAIL_ADDRESS, true);
    }

    @Test
    public void shouldReturn400IfRequestIsMissingNotificationType() {
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
    public void shouldReturn400IfSessionIdIsInvalid() {
        APIGatewayProxyResponseEvent result =
                makeCallWithCode("123456", VERIFY_EMAIL.toString(), Optional.empty(), CLIENT_ID);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1000));
    }

    @Test
    public void shouldReturn400IfNotificationTypeIsNotValid() {
        APIGatewayProxyResponseEvent result = makeCallWithCode(CODE, "VERIFY_TEXT");

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1001));
    }

    @Test
    public void shouldUpdateRedisWhenUserHasReachedMaxPhoneNumberCodeAttempts()
            throws JsonProcessingException {
        final String USER_INPUT = "123456";
        session.setState(PHONE_NUMBER_CODE_NOT_VALID);
        when(configurationService.getCodeMaxRetries()).thenReturn(5);
        when(configurationService.getCodeExpiry()).thenReturn(900L);

        when(validationService.validateVerificationCode(
                        eq(VERIFY_PHONE_NUMBER),
                        eq(Optional.of(CODE)),
                        eq(USER_INPUT),
                        any(Session.class),
                        eq(5)))
                .thenReturn(USER_ENTERED_INVALID_PHONE_VERIFICATION_CODE_TOO_MANY_TIMES);
        when(codeStorageService.getOtpCode(TEST_EMAIL_ADDRESS, VERIFY_PHONE_NUMBER))
                .thenReturn(Optional.of(CODE));

        APIGatewayProxyResponseEvent result =
                makeCallWithCode(USER_INPUT, VERIFY_PHONE_NUMBER.toString());

        BaseAPIResponse codeResponse =
                new ObjectMapper().readValue(result.getBody(), BaseAPIResponse.class);
        assertThat(result, hasStatus(400));
        assertThat(codeResponse.getSessionState(), equalTo(PHONE_NUMBER_CODE_MAX_RETRIES_REACHED));
        assertThat(session.getRetryCount(), equalTo(0));
        verify(authenticationService, never())
                .updatePhoneNumberVerifiedStatus(TEST_EMAIL_ADDRESS, true);
        verify(codeStorageService)
                .saveCodeBlockedForSession(TEST_EMAIL_ADDRESS, session.getSessionId(), 900);
    }

    @Test
    public void shouldReturnMaxReachedWhenPhoneNumberCodeIsBlocked()
            throws JsonProcessingException {
        final String USER_INPUT = "123456";
        session.setState(PHONE_NUMBER_CODE_NOT_VALID);
        when(codeStorageService.isCodeBlockedForSession(TEST_EMAIL_ADDRESS, session.getSessionId()))
                .thenReturn(true);

        APIGatewayProxyResponseEvent result =
                makeCallWithCode(USER_INPUT, VERIFY_PHONE_NUMBER.toString());

        BaseAPIResponse codeResponse =
                new ObjectMapper().readValue(result.getBody(), BaseAPIResponse.class);
        assertThat(result, hasStatus(400));
        assertThat(codeResponse.getSessionState(), equalTo(PHONE_NUMBER_CODE_MAX_RETRIES_REACHED));
        verify(codeStorageService, never())
                .getOtpCode(session.getEmailAddress(), VERIFY_PHONE_NUMBER);
    }

    @Test
    public void shouldUpdateRedisWhenUserHasReachedMaxEmailCodeAttempts()
            throws JsonProcessingException {
        session.setState(EMAIL_CODE_NOT_VALID);

        final String USER_INPUT = "123456";
        when(configurationService.getCodeMaxRetries()).thenReturn(5);
        when(configurationService.getCodeExpiry()).thenReturn(900L);
        when(validationService.validateVerificationCode(
                        eq(VERIFY_EMAIL),
                        eq(Optional.of(CODE)),
                        eq(USER_INPUT),
                        any(Session.class),
                        eq(5)))
                .thenReturn(USER_ENTERED_INVALID_EMAIL_VERIFICATION_CODE_TOO_MANY_TIMES);
        when(codeStorageService.getOtpCode(TEST_EMAIL_ADDRESS, VERIFY_EMAIL))
                .thenReturn(Optional.of(CODE));

        APIGatewayProxyResponseEvent result = makeCallWithCode(USER_INPUT, VERIFY_EMAIL.toString());

        BaseAPIResponse codeResponse =
                new ObjectMapper().readValue(result.getBody(), BaseAPIResponse.class);
        assertThat(result, hasStatus(400));
        assertThat(codeResponse.getSessionState(), equalTo(EMAIL_CODE_MAX_RETRIES_REACHED));
        assertThat(session.getRetryCount(), equalTo(0));
        verify(codeStorageService)
                .saveCodeBlockedForSession(TEST_EMAIL_ADDRESS, session.getSessionId(), 900);
    }

    @Test
    public void shouldReturnMaxReachedWhenEmailCodeIsBlocked() throws JsonProcessingException {
        session.setState(EMAIL_CODE_NOT_VALID);

        final String USER_INPUT = "123456";
        when(codeStorageService.isCodeBlockedForSession(TEST_EMAIL_ADDRESS, session.getSessionId()))
                .thenReturn(true);

        APIGatewayProxyResponseEvent result = makeCallWithCode(USER_INPUT, VERIFY_EMAIL.toString());

        BaseAPIResponse codeResponse =
                new ObjectMapper().readValue(result.getBody(), BaseAPIResponse.class);
        assertThat(result, hasStatus(400));
        assertThat(codeResponse.getSessionState(), equalTo(EMAIL_CODE_MAX_RETRIES_REACHED));
    }

    @Test
    public void shouldReturn200ForValidMfaSmsRequest() throws JsonProcessingException {
        session.setState(SessionState.MFA_SMS_CODE_SENT);

        when(configurationService.getCodeMaxRetries()).thenReturn(5);
        when(codeStorageService.getOtpCode(TEST_EMAIL_ADDRESS, MFA_SMS))
                .thenReturn(Optional.of(CODE));
        when(validationService.validateVerificationCode(
                        eq(MFA_SMS), eq(Optional.of(CODE)), eq(CODE), any(Session.class), eq(5)))
                .thenReturn(USER_ENTERED_VALID_MFA_CODE);

        when(stateMachine.transition(
                        eq(MFA_SMS_CODE_SENT),
                        eq(USER_ENTERED_VALID_MFA_CODE),
                        argThat(isContextWithUserProfile(userProfile))))
                .thenReturn(MFA_CODE_VERIFIED);

        APIGatewayProxyResponseEvent result = makeCallWithCode(CODE, MFA_SMS.toString());

        verify(codeStorageService).deleteOtpCode(TEST_EMAIL_ADDRESS, MFA_SMS);
        assertThat(result, hasStatus(200));
        BaseAPIResponse codeResponse =
                new ObjectMapper().readValue(result.getBody(), BaseAPIResponse.class);
        assertThat(codeResponse.getSessionState(), equalTo(MFA_CODE_VERIFIED));
    }

    @Test
    public void shouldReturnUpdateTermsAndConditionsStateIfUserHasNotAcceptedLatest()
            throws JsonProcessingException {
        session.setState(SessionState.MFA_SMS_CODE_SENT);

        when(configurationService.getCodeMaxRetries()).thenReturn(5);
        when(codeStorageService.getOtpCode(TEST_EMAIL_ADDRESS, MFA_SMS))
                .thenReturn(Optional.of(CODE));
        when(validationService.validateVerificationCode(
                        eq(MFA_SMS), eq(Optional.of(CODE)), eq(CODE), any(Session.class), eq(5)))
                .thenReturn(USER_ENTERED_VALID_MFA_CODE);

        when(stateMachine.transition(
                        eq(MFA_SMS_CODE_SENT),
                        eq(USER_ENTERED_VALID_MFA_CODE),
                        argThat(isContextWithUserProfile(userProfile))))
                .thenReturn(UPDATED_TERMS_AND_CONDITIONS);

        APIGatewayProxyResponseEvent result = makeCallWithCode(CODE, MFA_SMS.toString());

        verify(codeStorageService).deleteOtpCode(TEST_EMAIL_ADDRESS, MFA_SMS);
        assertThat(result, hasStatus(200));
        BaseAPIResponse codeResponse =
                new ObjectMapper().readValue(result.getBody(), BaseAPIResponse.class);
        assertThat(codeResponse.getSessionState(), equalTo(UPDATED_TERMS_AND_CONDITIONS));
    }

    @Test
    public void shouldReturnMfaCodeNotValidStateIfRequestCodeDoesNotMatchStoredCode()
            throws JsonProcessingException {
        session.setState(MFA_SMS_CODE_SENT);
        when(configurationService.getCodeMaxRetries()).thenReturn(5);
        when(codeStorageService.getOtpCode(TEST_EMAIL_ADDRESS, MFA_SMS))
                .thenReturn(Optional.of(CODE));
        when(validationService.validateVerificationCode(
                        eq(MFA_SMS),
                        eq(Optional.of(CODE)),
                        eq("123457"),
                        any(Session.class),
                        eq(5)))
                .thenReturn(USER_ENTERED_INVALID_MFA_CODE);

        APIGatewayProxyResponseEvent result = makeCallWithCode("123457", MFA_SMS.toString());

        BaseAPIResponse codeResponse =
                new ObjectMapper().readValue(result.getBody(), BaseAPIResponse.class);
        assertThat(result, hasStatus(400));
        assertThat(codeResponse.getSessionState(), equalTo(MFA_CODE_NOT_VALID));
    }

    @Test
    public void shouldUpdateRedisWhenUserHasReachedMaxMfaCodeAttempts()
            throws JsonProcessingException {
        session.setState(MFA_CODE_NOT_VALID);
        final String USER_INPUT = "123456";
        when(configurationService.getCodeMaxRetries()).thenReturn(5);
        when(configurationService.getCodeExpiry()).thenReturn(900L);
        when(validationService.validateVerificationCode(
                        eq(MFA_SMS),
                        eq(Optional.of(CODE)),
                        eq(USER_INPUT),
                        any(Session.class),
                        eq(5)))
                .thenReturn(USER_ENTERED_INVALID_MFA_CODE_TOO_MANY_TIMES);
        when(codeStorageService.getOtpCode(TEST_EMAIL_ADDRESS, MFA_SMS))
                .thenReturn(Optional.of(CODE));

        APIGatewayProxyResponseEvent result = makeCallWithCode(USER_INPUT, MFA_SMS.toString());

        BaseAPIResponse codeResponse =
                new ObjectMapper().readValue(result.getBody(), BaseAPIResponse.class);
        assertThat(result, hasStatus(400));
        assertThat(codeResponse.getSessionState(), equalTo(MFA_CODE_MAX_RETRIES_REACHED));
        assertThat(session.getRetryCount(), equalTo(0));
        verify(codeStorageService)
                .saveCodeBlockedForSession(TEST_EMAIL_ADDRESS, session.getSessionId(), 900);
    }

    @Test
    public void shouldReturnMaxReachedWhenMfaCodeIsBlocked() throws JsonProcessingException {
        final String USER_INPUT = "123456";
        session.setState(MFA_CODE_NOT_VALID);
        when(codeStorageService.isCodeBlockedForSession(TEST_EMAIL_ADDRESS, session.getSessionId()))
                .thenReturn(true);

        APIGatewayProxyResponseEvent result = makeCallWithCode(USER_INPUT, MFA_SMS.toString());

        BaseAPIResponse codeResponse =
                new ObjectMapper().readValue(result.getBody(), BaseAPIResponse.class);
        assertThat(result, hasStatus(400));
        assertThat(codeResponse.getSessionState(), equalTo(MFA_CODE_MAX_RETRIES_REACHED));
        verify(codeStorageService, never()).getOtpCode(session.getEmailAddress(), MFA_SMS);
    }

    @Test
    public void shouldReturn400IfUserTransitionsFromWrongStateForEmailCode() {
        session.setState(SessionState.NEW);
        when(configurationService.getCodeMaxRetries()).thenReturn(5);
        when(codeStorageService.getOtpCode(TEST_EMAIL_ADDRESS, VERIFY_EMAIL))
                .thenReturn(Optional.of(CODE));
        when(validationService.validateVerificationCode(
                        eq(VERIFY_EMAIL),
                        eq(Optional.of(CODE)),
                        eq(CODE),
                        any(Session.class),
                        eq(5)))
                .thenReturn(USER_ENTERED_VALID_EMAIL_VERIFICATION_CODE);
        when(stateMachine.transition(
                        eq(NEW),
                        eq(USER_ENTERED_VALID_EMAIL_VERIFICATION_CODE),
                        argThat(isContextWithUserProfile(userProfile))))
                .thenThrow(new StateMachine.InvalidStateTransitionException());

        APIGatewayProxyResponseEvent result = makeCallWithCode(CODE, VERIFY_EMAIL.toString());

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1017));
    }

    @Test
    public void shouldReturn200ForValidVerifyEmailRequestUsingTestClient()
            throws JsonProcessingException {
        testClientSession.setState(VERIFY_EMAIL_CODE_SENT);
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
                .thenReturn(USER_ENTERED_VALID_EMAIL_VERIFICATION_CODE);
        APIGatewayProxyResponseEvent result =
                makeCallWithCode(
                        TEST_CLIENT_CODE,
                        VERIFY_EMAIL.toString(),
                        Optional.of(testClientSession),
                        TEST_CLIENT_ID);

        verify(codeStorageService).deleteOtpCode(TEST_CLIENT_EMAIL, VERIFY_EMAIL);
        assertThat(result, hasStatus(200));
        BaseAPIResponse codeResponse =
                new ObjectMapper().readValue(result.getBody(), BaseAPIResponse.class);
        assertThat(codeResponse.getSessionState(), equalTo(EMAIL_CODE_VERIFIED));
    }

    private APIGatewayProxyResponseEvent makeCallWithCode(String code, String notificationType) {
        return makeCallWithCode(code, notificationType, Optional.of(session), CLIENT_ID);
    }

    private APIGatewayProxyResponseEvent makeCallWithCode(
            String code, String notificationType, Optional<Session> session, String clientId) {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(
                Map.of(
                        "Session-Id",
                        session.map(s -> s.getSessionId()).orElse("invalid-session-id"),
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
