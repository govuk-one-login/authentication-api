package uk.gov.di.authentication.api;

import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.authentication.frontendapi.entity.VerifyCodeRequest;
import uk.gov.di.authentication.frontendapi.lambda.VerifyCodeHandler;
import uk.gov.di.authentication.shared.entity.CodeRequestType;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.NotificationType;
import uk.gov.di.authentication.shared.entity.ServiceType;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.helpers.SaltHelper;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;
import uk.gov.di.authentication.sharedtest.extensions.AuthSessionExtension;
import uk.gov.di.authentication.sharedtest.extensions.AuthenticationAttemptsStoreExtension;
import uk.gov.di.authentication.sharedtest.helper.AuditAssertionsHelper;

import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_ACCOUNT_RECOVERY_BLOCK_REMOVED;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_CODE_MAX_RETRIES_REACHED;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_CODE_VERIFIED;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_INVALID_CODE_SENT;
import static uk.gov.di.authentication.shared.entity.NotificationType.MFA_SMS;
import static uk.gov.di.authentication.shared.entity.NotificationType.RESET_PASSWORD_WITH_CODE;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_CHANGE_HOW_GET_SECURITY_CODES;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_EMAIL;
import static uk.gov.di.authentication.shared.services.CodeStorageService.CODE_BLOCKED_KEY_PREFIX;
import static uk.gov.di.authentication.sharedtest.helper.AuditAssertionsHelper.assertTxmaAuditEventsReceived;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

public class VerifyCodeIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    private static final String EMAIL_ADDRESS = "test@test.com";
    private static final String PHONE_NUMBER = "+447712345432";
    private static final String CLIENT_ID = "test-client-id";
    private static final String REDIRECT_URI = "http://localhost/redirect";
    public static final String CLIENT_SESSION_ID = "a-client-session-id";
    public static final String CLIENT_NAME = "test-client-name";
    private static final Subject SUBJECT = new Subject();
    private static final String INTERNAl_SECTOR_HOST = "test.account.gov.uk";
    private String sessionId;

    @RegisterExtension
    protected static final AuthenticationAttemptsStoreExtension authCodeExtension =
            new AuthenticationAttemptsStoreExtension();

    @RegisterExtension
    protected static final AuthSessionExtension authSessionExtension = new AuthSessionExtension();

    @BeforeEach
    void setup() throws Json.JsonException {
        handler =
                new VerifyCodeHandler(
                        REAUTH_SIGNOUT_AND_TXMA_ENABLED_CONFIGUARION_SERVICE,
                        redisConnectionService);
        this.sessionId = redis.createSession();
        authSessionExtension.addSession(this.sessionId);
        authSessionExtension.addClientIdToSession(this.sessionId, CLIENT_ID);
        txmaAuditQueue.clear();
    }

    private static Stream<NotificationType> emailNotificationTypes() {
        return Stream.of(VERIFY_EMAIL, VERIFY_CHANGE_HOW_GET_SECURITY_CODES);
    }

    @ParameterizedTest
    @MethodSource("emailNotificationTypes")
    void shouldCallVerifyCodeEndpointToVerifyEmailCodeAndReturn204(
            NotificationType emailNotificationType) throws Json.JsonException {
        setUpTestWithoutSignUp(sessionId, withScope());
        String code = redis.generateAndSaveEmailCode(EMAIL_ADDRESS, 900, emailNotificationType);
        VerifyCodeRequest codeRequest = new VerifyCodeRequest(emailNotificationType, code);

        var response =
                makeRequest(
                        Optional.of(codeRequest),
                        constructFrontendHeaders(sessionId, CLIENT_SESSION_ID),
                        Map.of());
        assertThat(response, hasStatus(204));
        assertTxmaAuditEventsReceived(txmaAuditQueue, List.of(AUTH_CODE_VERIFIED));
    }

    @ParameterizedTest
    @MethodSource("emailNotificationTypes")
    void shouldResetCodeRequestCountWhenSuccessfulEmailCodeAndReturn204(
            NotificationType emailNotificationType) throws Json.JsonException {
        authSessionExtension.incrementSessionCodeRequestCount(
                sessionId, emailNotificationType, JourneyType.ACCOUNT_RECOVERY);
        authSessionExtension.incrementSessionCodeRequestCount(
                sessionId, emailNotificationType, JourneyType.ACCOUNT_RECOVERY);
        authSessionExtension.incrementSessionCodeRequestCount(
                sessionId, emailNotificationType, JourneyType.ACCOUNT_RECOVERY);
        setUpTestWithoutSignUp(sessionId, withScope());
        String code = redis.generateAndSaveEmailCode(EMAIL_ADDRESS, 900, emailNotificationType);
        VerifyCodeRequest codeRequest = new VerifyCodeRequest(emailNotificationType, code);

        var response =
                makeRequest(
                        Optional.of(codeRequest),
                        constructFrontendHeaders(sessionId, CLIENT_SESSION_ID),
                        Map.of());

        assertThat(response, hasStatus(204));
        assertThat(redis.getMfaCodeAttemptsCount(EMAIL_ADDRESS), equalTo(0));
        assertTxmaAuditEventsReceived(txmaAuditQueue, List.of(AUTH_CODE_VERIFIED));
    }

    @ParameterizedTest
    @MethodSource("emailNotificationTypes")
    void shouldCallVerifyCodeEndpointAndReturn400WhenEmailCodeHasExpired(
            NotificationType emailNotificationType)
            throws InterruptedException, Json.JsonException {
        setUpTestWithoutSignUp(sessionId, withScope());

        String code = redis.generateAndSaveEmailCode(EMAIL_ADDRESS, 2, emailNotificationType);
        VerifyCodeRequest codeRequest = new VerifyCodeRequest(emailNotificationType, code);

        TimeUnit.SECONDS.sleep(3);

        var response =
                makeRequest(
                        Optional.of(codeRequest),
                        constructFrontendHeaders(sessionId, CLIENT_SESSION_ID),
                        Map.of());

        assertThat(response, hasStatus(400));
        assertThat(response, hasJsonBody(ErrorResponse.ERROR_1036));

        assertTxmaAuditEventsReceived(txmaAuditQueue, List.of(AUTH_INVALID_CODE_SENT));
    }

    @ParameterizedTest
    @MethodSource("emailNotificationTypes")
    void shouldReturn400WithErrorWhenUserTriesEmailCodeThatTheyHaveAlreadyUsed(
            NotificationType emailNotificationType) throws Json.JsonException {
        setUpTestWithoutSignUp(sessionId, withScope());
        String code = redis.generateAndSaveEmailCode(EMAIL_ADDRESS, 900, emailNotificationType);
        VerifyCodeRequest codeRequest = new VerifyCodeRequest(emailNotificationType, code);

        var response =
                makeRequest(
                        Optional.of(codeRequest),
                        constructFrontendHeaders(sessionId, CLIENT_SESSION_ID),
                        Map.of());

        assertThat(response, hasStatus(204));

        var response2 =
                makeRequest(
                        Optional.of(codeRequest),
                        constructFrontendHeaders(sessionId, CLIENT_SESSION_ID),
                        Map.of());

        assertThat(response2, hasStatus(400));
        assertThat(response2, hasJsonBody(ErrorResponse.ERROR_1036));

        assertTxmaAuditEventsReceived(
                txmaAuditQueue, List.of(AUTH_CODE_VERIFIED, AUTH_INVALID_CODE_SENT));
    }

    @Test
    void shouldReturnMaxReachedButNotSetBlockWhenVerifyEmailCodeAttemptsExceedMaxRetryCount()
            throws Json.JsonException {
        setUpTestWithoutSignUp(sessionId, withScope());
        for (int i = 0; i < ConfigurationService.getInstance().getCodeMaxRetries(); i++) {
            redis.increaseMfaCodeAttemptsCount(EMAIL_ADDRESS);
        }
        var codeRequest = new VerifyCodeRequest(VERIFY_EMAIL, "123456");

        var response =
                makeRequest(
                        Optional.of(codeRequest),
                        constructFrontendHeaders(sessionId, CLIENT_SESSION_ID),
                        Map.of());

        var codeRequestType =
                CodeRequestType.getCodeRequestType(
                        codeRequest.notificationType(), JourneyType.REGISTRATION);
        var codeBlockedKeyPrefix = CODE_BLOCKED_KEY_PREFIX + codeRequestType;

        assertThat(response, hasStatus(400));
        assertThat(response, hasJsonBody(ErrorResponse.ERROR_1033));
        assertThat(
                redis.isBlockedMfaCodesForEmail(EMAIL_ADDRESS, codeBlockedKeyPrefix),
                equalTo(false));
        assertTxmaAuditEventsReceived(txmaAuditQueue, List.of(AUTH_CODE_MAX_RETRIES_REACHED));
    }

    @Test
    void shouldReturnMaxCodesReachedIfAccountRecoveryEmailCodeIsBlocked()
            throws Json.JsonException {
        setUpTestWithoutSignUp(sessionId, withScope());

        var codeRequestType =
                CodeRequestType.getCodeRequestType(
                        VERIFY_CHANGE_HOW_GET_SECURITY_CODES, JourneyType.ACCOUNT_RECOVERY);
        var codeBlockedKeyPrefix = CODE_BLOCKED_KEY_PREFIX + codeRequestType;
        redis.blockMfaCodesForEmail(EMAIL_ADDRESS, codeBlockedKeyPrefix);

        var codeRequest = new VerifyCodeRequest(VERIFY_CHANGE_HOW_GET_SECURITY_CODES, "123456");

        var response =
                makeRequest(
                        Optional.of(codeRequest),
                        constructFrontendHeaders(sessionId, CLIENT_SESSION_ID),
                        Map.of());

        assertThat(response, hasStatus(400));
        assertThat(response, hasJsonBody(ErrorResponse.ERROR_1048));

        AuditAssertionsHelper.assertNoTxmaAuditEventsReceived(txmaAuditQueue);
    }

    @Test
    void shouldReturnMaxReachedAndSetBlockWhenAccountRecoveryEmailCodeAttemptsExceedMaxRetryCount()
            throws Json.JsonException {
        setUpTestWithoutSignUp(sessionId, withScope());
        for (int i = 0; i < 6; i++) {
            redis.increaseMfaCodeAttemptsCount(EMAIL_ADDRESS);
        }
        var codeRequest = new VerifyCodeRequest(VERIFY_CHANGE_HOW_GET_SECURITY_CODES, "123456");

        var response =
                makeRequest(
                        Optional.of(codeRequest),
                        constructFrontendHeaders(sessionId, CLIENT_SESSION_ID),
                        Map.of());
        var codeRequestType =
                CodeRequestType.getCodeRequestType(
                        codeRequest.notificationType(), JourneyType.ACCOUNT_RECOVERY);
        var codeBlockedKeyPrefix = CODE_BLOCKED_KEY_PREFIX + codeRequestType;

        assertThat(response, hasStatus(400));
        assertThat(response, hasJsonBody(ErrorResponse.ERROR_1048));
        assertThat(
                redis.isBlockedMfaCodesForEmail(EMAIL_ADDRESS, codeBlockedKeyPrefix),
                equalTo(true));
        assertTxmaAuditEventsReceived(txmaAuditQueue, List.of(AUTH_CODE_MAX_RETRIES_REACHED));
    }

    @Test
    void shouldReturnMaxReachedAndSetBlockWhenPasswordResetEmailCodeAttemptsExceedMaxRetryCount()
            throws Json.JsonException {
        setUpTestWithSignUp(sessionId, withScope());
        for (int i = 0; i < 6; i++) {
            redis.increaseMfaCodeAttemptsCount(EMAIL_ADDRESS);
        }
        var codeRequest = new VerifyCodeRequest(RESET_PASSWORD_WITH_CODE, "123456");

        var response =
                makeRequest(
                        Optional.of(codeRequest),
                        constructFrontendHeaders(sessionId, CLIENT_SESSION_ID),
                        Map.of());
        var codeRequestType =
                CodeRequestType.getCodeRequestType(
                        codeRequest.notificationType(), JourneyType.PASSWORD_RESET);
        var codeBlockedKeyPrefix = CODE_BLOCKED_KEY_PREFIX + codeRequestType;

        assertThat(response, hasStatus(400));
        assertThat(response, hasJsonBody(ErrorResponse.ERROR_1039));
        assertThat(
                redis.isBlockedMfaCodesForEmail(EMAIL_ADDRESS, codeBlockedKeyPrefix),
                equalTo(true));
        assertTxmaAuditEventsReceived(txmaAuditQueue, List.of(AUTH_CODE_MAX_RETRIES_REACHED));
    }

    private static Stream<JourneyType> journeyTypes() {
        return Stream.of(
                JourneyType.SIGN_IN, JourneyType.PASSWORD_RESET_MFA, JourneyType.REAUTHENTICATION);
    }

    @ParameterizedTest
    @EnumSource(
            value = JourneyType.class,
            names = {"SIGN_IN", "PASSWORD_RESET_MFA"})
    void shouldReturnMaxReachedAndSetBlockWhenSignInSmsCodeAttemptsExceedMaxRetryCount(
            JourneyType journeyType) throws Json.JsonException {
        setUpTestWithSignUp(sessionId, withScope());
        userStore.addVerifiedPhoneNumber(EMAIL_ADDRESS, PHONE_NUMBER);
        for (int i = 0; i < 6; i++) {
            redis.increaseMfaCodeAttemptsCount(EMAIL_ADDRESS);
        }
        var codeRequest = new VerifyCodeRequest(MFA_SMS, "123456", journeyType);

        var response =
                makeRequest(
                        Optional.of(codeRequest),
                        constructFrontendHeaders(sessionId, CLIENT_SESSION_ID),
                        Map.of());
        var codeRequestType =
                CodeRequestType.getCodeRequestType(codeRequest.notificationType(), journeyType);
        var codeBlockedKeyPrefix = CODE_BLOCKED_KEY_PREFIX + codeRequestType;

        assertThat(response, hasStatus(400));
        assertThat(response, hasJsonBody(ErrorResponse.ERROR_1027));
        assertThat(
                redis.isBlockedMfaCodesForEmail(EMAIL_ADDRESS, codeBlockedKeyPrefix),
                equalTo(true));
        assertTxmaAuditEventsReceived(txmaAuditQueue, List.of(AUTH_CODE_MAX_RETRIES_REACHED));
    }

    @Test
    void shouldReturnMaxReachedAndSingalLogoutWhenReauthSmsCodeAttemptsExceedMaxRetryCount()
            throws Json.JsonException {
        setUpTestWithSignUp(sessionId, withScope());
        userStore.addVerifiedPhoneNumber(EMAIL_ADDRESS, PHONE_NUMBER);
        for (int i = 0; i < 5; i++) {
            redis.increaseMfaCodeAttemptsCount(EMAIL_ADDRESS);
        }
        var codeRequest = new VerifyCodeRequest(MFA_SMS, "123456", JourneyType.REAUTHENTICATION);

        var response =
                makeRequest(
                        Optional.of(codeRequest),
                        constructFrontendHeaders(sessionId, CLIENT_SESSION_ID),
                        Map.of());

        assertThat(response, hasStatus(400));
        assertThat(response, hasJsonBody(ErrorResponse.ERROR_1035));
        assertThat(
                authSessionExtension.getSession(sessionId).get().getVerifiedMfaMethodType(),
                equalTo(null));
    }

    @ParameterizedTest
    @MethodSource("journeyTypes")
    void shouldReturn204WhenUserEntersValidMfaSmsCode(JourneyType journeyType) throws Exception {
        var internalCommonSubjectId =
                ClientSubjectHelper.calculatePairwiseIdentifier(
                        SUBJECT.getValue(), INTERNAl_SECTOR_HOST, SaltHelper.generateNewSalt());
        authSessionExtension.addInternalCommonSubjectIdToSession(
                this.sessionId, internalCommonSubjectId);
        setUpTestWithoutSignUp(sessionId, withScope());
        userStore.signUp(EMAIL_ADDRESS, "password", SUBJECT);
        userStore.addVerifiedPhoneNumber(EMAIL_ADDRESS, PHONE_NUMBER);
        userStore.updateTermsAndConditions(EMAIL_ADDRESS, "1.0");

        var code = redis.generateAndSaveMfaCode(EMAIL_ADDRESS.concat(PHONE_NUMBER), 900);
        var codeRequest = new VerifyCodeRequest(NotificationType.MFA_SMS, code, journeyType);

        var response =
                makeRequest(
                        Optional.of(codeRequest),
                        constructFrontendHeaders(sessionId, CLIENT_SESSION_ID),
                        Map.of());

        assertThat(response, hasStatus(204));

        assertThat(accountModifiersStore.isBlockPresent(internalCommonSubjectId), equalTo(false));
        assertTxmaAuditEventsReceived(txmaAuditQueue, List.of(AUTH_CODE_VERIFIED));
        assertThat(
                authSessionExtension.getSession(sessionId).get().getVerifiedMfaMethodType(),
                equalTo(MFAMethodType.SMS));
    }

    @ParameterizedTest
    @MethodSource("journeyTypes")
    void shouldReturn204WhenUserEntersValidMfaSmsCodeAndClearAccountRecoveryBlockWhenPresent(
            JourneyType journeyType) throws Exception {
        var internalCommonSubjectId =
                ClientSubjectHelper.calculatePairwiseIdentifier(
                        SUBJECT.getValue(), INTERNAl_SECTOR_HOST, SaltHelper.generateNewSalt());
        accountModifiersStore.setAccountRecoveryBlock(internalCommonSubjectId);
        authSessionExtension.addInternalCommonSubjectIdToSession(
                this.sessionId, internalCommonSubjectId);
        setUpTestWithoutSignUp(sessionId, withScope());
        userStore.signUp(EMAIL_ADDRESS, "password", SUBJECT);
        userStore.addVerifiedPhoneNumber(EMAIL_ADDRESS, PHONE_NUMBER);
        userStore.updateTermsAndConditions(EMAIL_ADDRESS, "1.0");

        var code = redis.generateAndSaveMfaCode(EMAIL_ADDRESS.concat(PHONE_NUMBER), 900);
        var codeRequest = new VerifyCodeRequest(NotificationType.MFA_SMS, code, journeyType);

        var response =
                makeRequest(
                        Optional.of(codeRequest),
                        constructFrontendHeaders(sessionId, CLIENT_SESSION_ID),
                        Map.of());

        assertThat(response, hasStatus(204));
        assertThat(accountModifiersStore.isBlockPresent(internalCommonSubjectId), equalTo(false));
        assertTxmaAuditEventsReceived(
                txmaAuditQueue, List.of(AUTH_CODE_VERIFIED, AUTH_ACCOUNT_RECOVERY_BLOCK_REMOVED));
        assertThat(
                authSessionExtension.getSession(sessionId).get().getVerifiedMfaMethodType(),
                equalTo(MFAMethodType.SMS));
    }

    @Test
    void shouldReturn204WhenUserEntersValidMfaSmsCodeAndSessionCommonSubjectIdNotPresent()
            throws Exception {
        setUpTestWithoutSignUp(sessionId, withScope());
        userStore.signUp(EMAIL_ADDRESS, "password", SUBJECT);
        userStore.addVerifiedPhoneNumber(EMAIL_ADDRESS, PHONE_NUMBER);
        userStore.updateTermsAndConditions(EMAIL_ADDRESS, "1.0");

        var code = redis.generateAndSaveMfaCode(EMAIL_ADDRESS.concat(PHONE_NUMBER), 900);
        var codeRequest =
                new VerifyCodeRequest(
                        NotificationType.MFA_SMS, code, JourneyType.PASSWORD_RESET_MFA);

        var response =
                makeRequest(
                        Optional.of(codeRequest),
                        constructFrontendHeaders(sessionId, CLIENT_SESSION_ID),
                        Map.of());

        assertThat(response, hasStatus(204));
        var authSession = authSessionExtension.getSession(sessionId).orElseThrow();
        assertThat(authSession.getInternalCommonSubjectId(), notNullValue());
        assertTxmaAuditEventsReceived(txmaAuditQueue, List.of(AUTH_CODE_VERIFIED));
        assertThat(
                authSessionExtension.getSession(sessionId).get().getVerifiedMfaMethodType(),
                equalTo(MFAMethodType.SMS));
    }

    @ParameterizedTest
    @MethodSource("journeyTypes")
    void shouldReturn400WhenInvalidMfaSmsCodeIsEnteredAndNotClearAccountRecoveryBlockWhenPresent(
            JourneyType journeyType) throws Json.JsonException {
        var internalCommonSubjectId =
                ClientSubjectHelper.calculatePairwiseIdentifier(
                        SUBJECT.getValue(), INTERNAl_SECTOR_HOST, SaltHelper.generateNewSalt());
        accountModifiersStore.setAccountRecoveryBlock(internalCommonSubjectId);
        authSessionExtension.addInternalCommonSubjectIdToSession(
                this.sessionId, internalCommonSubjectId);
        setUpTestWithSignUp(sessionId, withScope());
        userStore.addVerifiedPhoneNumber(EMAIL_ADDRESS, PHONE_NUMBER);
        userStore.updateTermsAndConditions(EMAIL_ADDRESS, "1.0");

        redis.generateAndSaveMfaCode(EMAIL_ADDRESS.concat(PHONE_NUMBER).concat("123123"), 900);
        var codeRequest = new VerifyCodeRequest(NotificationType.MFA_SMS, "123456", journeyType);

        var response =
                makeRequest(
                        Optional.of(codeRequest),
                        constructFrontendHeaders(sessionId, CLIENT_SESSION_ID),
                        Map.of());

        assertThat(response, hasStatus(400));
        assertThat(accountModifiersStore.isBlockPresent(internalCommonSubjectId), equalTo(true));
        if (journeyType != JourneyType.REAUTHENTICATION) {
            assertTxmaAuditEventsReceived(txmaAuditQueue, List.of(AUTH_INVALID_CODE_SENT));
        }
        assertThat(
                authSessionExtension.getSession(sessionId).get().getVerifiedMfaMethodType(),
                equalTo(null));
    }

    private void setUpTestWithoutSignUp(String sessionId, Scope scope) throws Json.JsonException {
        authSessionExtension.addEmailToSession(sessionId, EMAIL_ADDRESS);
        AuthenticationRequest authRequest =
                new AuthenticationRequest.Builder(
                                ResponseType.CODE,
                                scope,
                                new ClientID(CLIENT_ID),
                                URI.create(REDIRECT_URI))
                        .nonce(new Nonce())
                        .state(new State())
                        .build();
        redis.createClientSession(CLIENT_SESSION_ID, CLIENT_NAME, authRequest.toParameters());
        clientStore.registerClient(
                CLIENT_ID,
                "test-client",
                singletonList("redirect-url"),
                singletonList(EMAIL_ADDRESS),
                List.of("openid", "email", "phone"),
                "public-key",
                singletonList("http://localhost/post-redirect-logout"),
                "http://example.com",
                String.valueOf(ServiceType.MANDATORY),
                "https://test.com",
                "public");
    }

    private void setUpTestWithSignUp(String sessionId, Scope scope) throws Json.JsonException {
        setUpTestWithoutSignUp(sessionId, scope);
        userStore.signUp(EMAIL_ADDRESS, "password");
    }

    private Scope withScope() {
        Scope scope = new Scope();
        scope.add(OIDCScopeValue.OPENID);
        scope.add(OIDCScopeValue.EMAIL);
        return scope;
    }
}
