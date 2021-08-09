package uk.gov.di.lambdas;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.entity.BaseAPIResponse;
import uk.gov.di.entity.ErrorResponse;
import uk.gov.di.entity.Session;
import uk.gov.di.entity.SessionState;
import uk.gov.di.services.CodeStorageService;
import uk.gov.di.services.ConfigurationService;
import uk.gov.di.services.DynamoService;
import uk.gov.di.services.SessionService;
import uk.gov.di.services.ValidationService;

import java.util.Map;
import java.util.Optional;

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.entity.NotificationType.MFA_SMS;
import static uk.gov.di.entity.NotificationType.VERIFY_EMAIL;
import static uk.gov.di.entity.NotificationType.VERIFY_PHONE_NUMBER;
import static uk.gov.di.entity.SessionState.EMAIL_CODE_MAX_RETRIES_REACHED;
import static uk.gov.di.entity.SessionState.EMAIL_CODE_NOT_VALID;
import static uk.gov.di.entity.SessionState.EMAIL_CODE_VERIFIED;
import static uk.gov.di.entity.SessionState.MFA_CODE_MAX_RETRIES_REACHED;
import static uk.gov.di.entity.SessionState.MFA_CODE_NOT_VALID;
import static uk.gov.di.entity.SessionState.MFA_CODE_VERIFIED;
import static uk.gov.di.entity.SessionState.PHONE_NUMBER_CODE_MAX_RETRIES_REACHED;
import static uk.gov.di.entity.SessionState.PHONE_NUMBER_CODE_NOT_VALID;
import static uk.gov.di.entity.SessionState.PHONE_NUMBER_CODE_VERIFIED;
import static uk.gov.di.entity.SessionState.VERIFY_EMAIL_CODE_SENT;
import static uk.gov.di.entity.SessionState.VERIFY_PHONE_NUMBER_CODE_SENT;
import static uk.gov.di.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class VerifyCodeRequestHandlerTest {

    private static final String TEST_EMAIL_ADDRESS = "test@test.com";
    private static final String CODE = "123456";
    private final Context context = mock(Context.class);
    private final SessionService sessionService = mock(SessionService.class);
    private final CodeStorageService codeStorageService = mock(CodeStorageService.class);
    private final DynamoService dynamoService = mock(DynamoService.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final ValidationService validationService = mock(ValidationService.class);
    private final Session session =
            new Session("session-id")
                    .setEmailAddress(TEST_EMAIL_ADDRESS)
                    .setState(VERIFY_EMAIL_CODE_SENT);
    private VerifyCodeHandler handler;

    @BeforeEach
    public void setup() {
        handler =
                new VerifyCodeHandler(
                        sessionService,
                        codeStorageService,
                        dynamoService,
                        configurationService,
                        validationService);
    }

    @Test
    public void shouldReturn200ForValidVerifyEmailRequest() throws JsonProcessingException {
        when(configurationService.getCodeMaxRetries()).thenReturn(5);
        when(codeStorageService.getOtpCode(TEST_EMAIL_ADDRESS, VERIFY_EMAIL))
                .thenReturn(Optional.of(CODE));
        when(validationService.validateEmailVerificationCode(
                        eq(Optional.of(CODE)), eq(CODE), any(Session.class), eq(5)))
                .thenReturn(EMAIL_CODE_VERIFIED);
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
        when(validationService.validatePhoneVerificationCode(
                        eq(Optional.of(CODE)), eq(CODE), any(Session.class), eq(5)))
                .thenReturn(PHONE_NUMBER_CODE_VERIFIED);
        when(codeStorageService.getOtpCode(TEST_EMAIL_ADDRESS, VERIFY_PHONE_NUMBER))
                .thenReturn(Optional.of(CODE));

        APIGatewayProxyResponseEvent result =
                makeCallWithCode(CODE, VERIFY_PHONE_NUMBER.toString());

        verify(codeStorageService).deleteOtpCode(TEST_EMAIL_ADDRESS, VERIFY_PHONE_NUMBER);
        verify(dynamoService).updatePhoneNumberVerifiedStatus(TEST_EMAIL_ADDRESS, true);
        assertThat(result, hasStatus(200));
        BaseAPIResponse codeResponse =
                new ObjectMapper().readValue(result.getBody(), BaseAPIResponse.class);
        assertThat(codeResponse.getSessionState(), equalTo(PHONE_NUMBER_CODE_VERIFIED));
    }

    @Test
    public void shouldReturnEmailCodeNotValidStateIfRequestCodeDoesNotMatchStoredCode()
            throws JsonProcessingException {
        when(configurationService.getCodeMaxRetries()).thenReturn(5);
        when(codeStorageService.getOtpCode(TEST_EMAIL_ADDRESS, VERIFY_EMAIL))
                .thenReturn(Optional.of(CODE));
        when(validationService.validateEmailVerificationCode(
                        eq(Optional.of(CODE)), eq("123457"), any(Session.class), eq(5)))
                .thenReturn(EMAIL_CODE_NOT_VALID);

        APIGatewayProxyResponseEvent result = makeCallWithCode("123457", VERIFY_EMAIL.toString());

        BaseAPIResponse codeResponse =
                new ObjectMapper().readValue(result.getBody(), BaseAPIResponse.class);
        assertThat(result, hasStatus(200));
        assertThat(codeResponse.getSessionState(), equalTo(EMAIL_CODE_NOT_VALID));
    }

    @Test
    public void shouldReturnPhoneNumberCodeNotValidStateIfRequestCodeDoesNotMatchStoredCode()
            throws JsonProcessingException {
        session.setState(VERIFY_PHONE_NUMBER_CODE_SENT);
        when(configurationService.getCodeMaxRetries()).thenReturn(5);
        when(validationService.validatePhoneVerificationCode(
                        eq(Optional.of(CODE)), eq(CODE), any(Session.class), eq(5)))
                .thenReturn(PHONE_NUMBER_CODE_NOT_VALID);
        when(codeStorageService.getOtpCode(TEST_EMAIL_ADDRESS, VERIFY_PHONE_NUMBER))
                .thenReturn(Optional.of(CODE));

        APIGatewayProxyResponseEvent result =
                makeCallWithCode(CODE, VERIFY_PHONE_NUMBER.toString());

        BaseAPIResponse codeResponse =
                new ObjectMapper().readValue(result.getBody(), BaseAPIResponse.class);
        assertThat(result, hasStatus(200));
        assertThat(codeResponse.getSessionState(), equalTo(PHONE_NUMBER_CODE_NOT_VALID));
        verify(dynamoService, never()).updatePhoneNumberVerifiedStatus(TEST_EMAIL_ADDRESS, true);
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
                makeCallWithCode("123456", VERIFY_EMAIL.toString(), Optional.empty());

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
        when(validationService.validatePhoneVerificationCode(
                        eq(Optional.of(CODE)), eq(USER_INPUT), any(Session.class), eq(5)))
                .thenReturn(PHONE_NUMBER_CODE_MAX_RETRIES_REACHED);
        when(codeStorageService.getOtpCode(TEST_EMAIL_ADDRESS, VERIFY_PHONE_NUMBER))
                .thenReturn(Optional.of(CODE));

        APIGatewayProxyResponseEvent result =
                makeCallWithCode(USER_INPUT, VERIFY_PHONE_NUMBER.toString());

        BaseAPIResponse codeResponse =
                new ObjectMapper().readValue(result.getBody(), BaseAPIResponse.class);
        assertThat(result, hasStatus(200));
        assertThat(codeResponse.getSessionState(), equalTo(PHONE_NUMBER_CODE_MAX_RETRIES_REACHED));
        assertThat(session.getRetryCount(), equalTo(0));
        verify(dynamoService, never()).updatePhoneNumberVerifiedStatus(TEST_EMAIL_ADDRESS, true);
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
        assertThat(result, hasStatus(200));
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
        when(validationService.validateEmailVerificationCode(
                        eq(Optional.of(CODE)), eq(USER_INPUT), any(Session.class), eq(5)))
                .thenReturn(EMAIL_CODE_MAX_RETRIES_REACHED);
        when(codeStorageService.getOtpCode(TEST_EMAIL_ADDRESS, VERIFY_EMAIL))
                .thenReturn(Optional.of(CODE));

        APIGatewayProxyResponseEvent result = makeCallWithCode(USER_INPUT, VERIFY_EMAIL.toString());

        BaseAPIResponse codeResponse =
                new ObjectMapper().readValue(result.getBody(), BaseAPIResponse.class);
        assertThat(result, hasStatus(200));
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
        assertThat(result, hasStatus(200));
        assertThat(codeResponse.getSessionState(), equalTo(EMAIL_CODE_MAX_RETRIES_REACHED));
    }

    @Test
    public void shouldReturn200ForValiMfaSmsRequest() throws JsonProcessingException {
        when(configurationService.getCodeMaxRetries()).thenReturn(5);
        when(codeStorageService.getOtpCode(TEST_EMAIL_ADDRESS, MFA_SMS))
                .thenReturn(Optional.of(CODE));
        when(validationService.validateMfaVerificationCode(
                        eq(Optional.of(CODE)), eq(CODE), any(Session.class), eq(5)))
                .thenReturn(MFA_CODE_VERIFIED);
        APIGatewayProxyResponseEvent result = makeCallWithCode(CODE, MFA_SMS.toString());

        verify(codeStorageService).deleteOtpCode(TEST_EMAIL_ADDRESS, MFA_SMS);
        assertThat(result, hasStatus(200));
        BaseAPIResponse codeResponse =
                new ObjectMapper().readValue(result.getBody(), BaseAPIResponse.class);
        assertThat(codeResponse.getSessionState(), equalTo(MFA_CODE_VERIFIED));
    }

    @Test
    public void shouldReturnMfaCodeNotValidStateIfRequestCodeDoesNotMatchStoredCode()
            throws JsonProcessingException {
        when(configurationService.getCodeMaxRetries()).thenReturn(5);
        when(codeStorageService.getOtpCode(TEST_EMAIL_ADDRESS, MFA_SMS))
                .thenReturn(Optional.of(CODE));
        when(validationService.validateMfaVerificationCode(
                        eq(Optional.of(CODE)), eq("123457"), any(Session.class), eq(5)))
                .thenReturn(MFA_CODE_NOT_VALID);

        APIGatewayProxyResponseEvent result = makeCallWithCode("123457", MFA_SMS.toString());

        BaseAPIResponse codeResponse =
                new ObjectMapper().readValue(result.getBody(), BaseAPIResponse.class);
        assertThat(result, hasStatus(200));
        assertThat(codeResponse.getSessionState(), equalTo(MFA_CODE_NOT_VALID));
    }

    @Test
    public void shouldUpdateRedisWhenUserHasReachedMaxMfaCodeAttempts()
            throws JsonProcessingException {
        final String USER_INPUT = "123456";
        when(configurationService.getCodeMaxRetries()).thenReturn(5);
        when(configurationService.getCodeExpiry()).thenReturn(900L);
        when(validationService.validateMfaVerificationCode(
                        eq(Optional.of(CODE)), eq(USER_INPUT), any(Session.class), eq(5)))
                .thenReturn(MFA_CODE_MAX_RETRIES_REACHED);
        when(codeStorageService.getOtpCode(TEST_EMAIL_ADDRESS, MFA_SMS))
                .thenReturn(Optional.of(CODE));

        APIGatewayProxyResponseEvent result = makeCallWithCode(USER_INPUT, MFA_SMS.toString());

        BaseAPIResponse codeResponse =
                new ObjectMapper().readValue(result.getBody(), BaseAPIResponse.class);
        assertThat(result, hasStatus(200));
        assertThat(codeResponse.getSessionState(), equalTo(MFA_CODE_MAX_RETRIES_REACHED));
        assertThat(session.getRetryCount(), equalTo(0));
        verify(codeStorageService)
                .saveCodeBlockedForSession(TEST_EMAIL_ADDRESS, session.getSessionId(), 900);
    }

    @Test
    public void shouldReturnMaxReachedWhenMfaCodeIsBlocked() throws JsonProcessingException {
        final String USER_INPUT = "123456";
        when(codeStorageService.isCodeBlockedForSession(TEST_EMAIL_ADDRESS, session.getSessionId()))
                .thenReturn(true);

        APIGatewayProxyResponseEvent result = makeCallWithCode(USER_INPUT, MFA_SMS.toString());

        BaseAPIResponse codeResponse =
                new ObjectMapper().readValue(result.getBody(), BaseAPIResponse.class);
        assertThat(result, hasStatus(200));
        assertThat(codeResponse.getSessionState(), equalTo(MFA_CODE_MAX_RETRIES_REACHED));
        verify(codeStorageService, never()).getOtpCode(session.getEmailAddress(), MFA_SMS);
    }

    @Test
    public void shouldReturn400IfUserTransitionsFromWrongStateForEmailCode() {
        session.setState(SessionState.NEW);

        when(configurationService.getCodeMaxRetries()).thenReturn(5);
        when(codeStorageService.getOtpCode(TEST_EMAIL_ADDRESS, VERIFY_EMAIL))
                .thenReturn(Optional.of(CODE));
        when(validationService.validateEmailVerificationCode(
                        eq(Optional.of(CODE)), eq(CODE), any(Session.class), eq(5)))
                .thenReturn(EMAIL_CODE_VERIFIED);
        APIGatewayProxyResponseEvent result = makeCallWithCode(CODE, VERIFY_EMAIL.toString());

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1019));
    }

    private APIGatewayProxyResponseEvent makeCallWithCode(String code, String notificationType) {
        return makeCallWithCode(code, notificationType, Optional.of(session));
    }

    private APIGatewayProxyResponseEvent makeCallWithCode(
            String code, String notificationType, Optional<Session> session) {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(
                Map.of(
                        "Session-Id",
                        session.map(s -> s.getSessionId()).orElse("invalid-session-id")));
        event.setBody(
                format(
                        "{ \"code\": \"%s\", \"notificationType\": \"%s\" }",
                        code, notificationType));
        when(sessionService.getSessionFromRequestHeaders(event.getHeaders())).thenReturn(session);
        return handler.handleRequest(event, context);
    }
}
