package uk.gov.di.authentication.api;

import com.nimbusds.oauth2.sdk.id.Subject;
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
import uk.gov.di.authentication.shared.entity.mfa.MFAMethod;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.helpers.IdGenerator;
import uk.gov.di.authentication.shared.helpers.SaltHelper;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;
import uk.gov.di.authentication.sharedtest.extensions.AuthSessionExtension;
import uk.gov.di.authentication.sharedtest.extensions.AuthenticationAttemptsStoreExtension;
import uk.gov.di.authentication.sharedtest.helper.AuditAssertionsHelper;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

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
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.BACKUP_SMS_METHOD;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.DEFAULT_SMS_METHOD;
import static uk.gov.di.authentication.shared.services.CodeStorageService.CODE_BLOCKED_KEY_PREFIX;
import static uk.gov.di.authentication.sharedtest.helper.AuditAssertionsHelper.assertTxmaAuditEventsReceived;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

public class VerifyCodeIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    private static final String EMAIL_ADDRESS = "test@test.com";
    private static final String PHONE_NUMBER = "+447712345432";
    private static final String CLIENT_ID = "test-client-id";
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
        this.sessionId = IdGenerator.generate();
        authSessionExtension.addSession(this.sessionId);
        authSessionExtension.addClientIdToSession(this.sessionId, CLIENT_ID);
        authSessionExtension.addClientNameToSession(this.sessionId, CLIENT_NAME);
        txmaAuditQueue.clear();
    }

    private static Stream<NotificationType> emailNotificationTypes() {
        return Stream.of(VERIFY_EMAIL, VERIFY_CHANGE_HOW_GET_SECURITY_CODES);
    }

    @ParameterizedTest
    @MethodSource("emailNotificationTypes")
    void shouldCallVerifyCodeEndpointToVerifyEmailCodeAndReturn204(
            NotificationType emailNotificationType) {
        setUpTestWithoutSignUp(sessionId);
        String code = redis.generateAndSaveEmailCode(EMAIL_ADDRESS, 900, emailNotificationType);
        VerifyCodeRequest codeRequest =
                new VerifyCodeRequest(emailNotificationType, code, null, null);

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
            NotificationType emailNotificationType) {
        authSessionExtension.incrementSessionCodeRequestCount(
                sessionId, emailNotificationType, JourneyType.ACCOUNT_RECOVERY);
        authSessionExtension.incrementSessionCodeRequestCount(
                sessionId, emailNotificationType, JourneyType.ACCOUNT_RECOVERY);
        authSessionExtension.incrementSessionCodeRequestCount(
                sessionId, emailNotificationType, JourneyType.ACCOUNT_RECOVERY);
        setUpTestWithoutSignUp(sessionId);
        String code = redis.generateAndSaveEmailCode(EMAIL_ADDRESS, 900, emailNotificationType);
        VerifyCodeRequest codeRequest =
                new VerifyCodeRequest(emailNotificationType, code, null, null);

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
            NotificationType emailNotificationType) throws InterruptedException {
        setUpTestWithoutSignUp(sessionId);

        String code = redis.generateAndSaveEmailCode(EMAIL_ADDRESS, 2, emailNotificationType);
        VerifyCodeRequest codeRequest =
                new VerifyCodeRequest(emailNotificationType, code, null, null);

        TimeUnit.SECONDS.sleep(3);

        var response =
                makeRequest(
                        Optional.of(codeRequest),
                        constructFrontendHeaders(sessionId, CLIENT_SESSION_ID),
                        Map.of());

        assertThat(response, hasStatus(400));
        assertThat(response, hasJsonBody(ErrorResponse.INVALID_EMAIL_CODE_ENTERED));

        assertTxmaAuditEventsReceived(txmaAuditQueue, List.of(AUTH_INVALID_CODE_SENT));
    }

    @ParameterizedTest
    @MethodSource("emailNotificationTypes")
    void shouldReturn400WithErrorWhenUserTriesEmailCodeThatTheyHaveAlreadyUsed(
            NotificationType emailNotificationType) {
        setUpTestWithoutSignUp(sessionId);
        String code = redis.generateAndSaveEmailCode(EMAIL_ADDRESS, 900, emailNotificationType);
        VerifyCodeRequest codeRequest =
                new VerifyCodeRequest(emailNotificationType, code, null, null);

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
        assertThat(response2, hasJsonBody(ErrorResponse.INVALID_EMAIL_CODE_ENTERED));

        assertTxmaAuditEventsReceived(
                txmaAuditQueue, List.of(AUTH_CODE_VERIFIED, AUTH_INVALID_CODE_SENT));
    }

    @Test
    void shouldReturnMaxReachedButNotSetBlockWhenVerifyEmailCodeAttemptsExceedMaxRetryCount() {
        setUpTestWithoutSignUp(sessionId);
        for (int i = 0; i < ConfigurationService.getInstance().getCodeMaxRetries(); i++) {
            redis.increaseMfaCodeAttemptsCount(EMAIL_ADDRESS);
        }
        var codeRequest = new VerifyCodeRequest(VERIFY_EMAIL, "123456", null, null);

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
        assertThat(response, hasJsonBody(ErrorResponse.TOO_MANY_EMAIL_CODES_ENTERED));
        assertThat(
                redis.isBlockedMfaCodesForEmail(EMAIL_ADDRESS, codeBlockedKeyPrefix),
                equalTo(false));
        assertTxmaAuditEventsReceived(txmaAuditQueue, List.of(AUTH_CODE_MAX_RETRIES_REACHED));
    }

    @Test
    void shouldReturnMaxCodesReachedIfAccountRecoveryEmailCodeIsBlocked() {
        setUpTestWithoutSignUp(sessionId);

        var codeRequestType =
                CodeRequestType.getCodeRequestType(
                        VERIFY_CHANGE_HOW_GET_SECURITY_CODES, JourneyType.ACCOUNT_RECOVERY);
        var codeBlockedKeyPrefix = CODE_BLOCKED_KEY_PREFIX + codeRequestType;
        redis.blockMfaCodesForEmail(EMAIL_ADDRESS, codeBlockedKeyPrefix);

        var codeRequest =
                new VerifyCodeRequest(VERIFY_CHANGE_HOW_GET_SECURITY_CODES, "123456", null, null);

        var response =
                makeRequest(
                        Optional.of(codeRequest),
                        constructFrontendHeaders(sessionId, CLIENT_SESSION_ID),
                        Map.of());

        assertThat(response, hasStatus(400));
        assertThat(response, hasJsonBody(ErrorResponse.TOO_MANY_EMAIL_CODES_FOR_MFA_RESET_ENTERED));

        AuditAssertionsHelper.assertNoTxmaAuditEventsReceived(txmaAuditQueue);
    }

    @Test
    void
            shouldReturnMaxReachedAndSetBlockWhenAccountRecoveryEmailCodeAttemptsExceedMaxRetryCount() {
        setUpTestWithoutSignUp(sessionId);
        for (int i = 0; i < 6; i++) {
            redis.increaseMfaCodeAttemptsCount(EMAIL_ADDRESS);
        }
        var codeRequest =
                new VerifyCodeRequest(VERIFY_CHANGE_HOW_GET_SECURITY_CODES, "123456", null, null);

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
        assertThat(response, hasJsonBody(ErrorResponse.TOO_MANY_EMAIL_CODES_FOR_MFA_RESET_ENTERED));
        assertThat(
                redis.isBlockedMfaCodesForEmail(EMAIL_ADDRESS, codeBlockedKeyPrefix),
                equalTo(true));
        assertTxmaAuditEventsReceived(txmaAuditQueue, List.of(AUTH_CODE_MAX_RETRIES_REACHED));
    }

    @Test
    void shouldReturnMaxReachedAndSetBlockWhenPasswordResetEmailCodeAttemptsExceedMaxRetryCount() {
        setUpTestWithSignUp(sessionId);
        for (int i = 0; i < 6; i++) {
            redis.increaseMfaCodeAttemptsCount(EMAIL_ADDRESS);
        }
        var codeRequest = new VerifyCodeRequest(RESET_PASSWORD_WITH_CODE, "123456", null, null);

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
        assertThat(response, hasJsonBody(ErrorResponse.TOO_MANY_INVALID_PW_RESET_CODES_ENTERED));
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
            JourneyType journeyType) {
        setUpTestWithSignUp(sessionId);
        userStore.addVerifiedPhoneNumber(EMAIL_ADDRESS, PHONE_NUMBER);
        for (int i = 0; i < 6; i++) {
            redis.increaseMfaCodeAttemptsCount(EMAIL_ADDRESS);
        }
        var codeRequest = new VerifyCodeRequest(MFA_SMS, "123456", journeyType, null);

        var response =
                makeRequest(
                        Optional.of(codeRequest),
                        constructFrontendHeaders(sessionId, CLIENT_SESSION_ID),
                        Map.of());
        var codeRequestType =
                CodeRequestType.getCodeRequestType(codeRequest.notificationType(), journeyType);
        var codeBlockedKeyPrefix = CODE_BLOCKED_KEY_PREFIX + codeRequestType;

        assertThat(response, hasStatus(400));
        assertThat(response, hasJsonBody(ErrorResponse.TOO_MANY_INVALID_MFA_OTPS_ENTERED));
        assertThat(
                redis.isBlockedMfaCodesForEmail(EMAIL_ADDRESS, codeBlockedKeyPrefix),
                equalTo(true));
        assertTxmaAuditEventsReceived(txmaAuditQueue, List.of(AUTH_CODE_MAX_RETRIES_REACHED));
    }

    @Test
    void shouldReturnMaxReachedAndSingalLogoutWhenReauthSmsCodeAttemptsExceedMaxRetryCount() {
        setUpTestWithSignUp(sessionId);
        userStore.addVerifiedPhoneNumber(EMAIL_ADDRESS, PHONE_NUMBER);
        for (int i = 0; i < 5; i++) {
            redis.increaseMfaCodeAttemptsCount(EMAIL_ADDRESS);
        }
        var codeRequest =
                new VerifyCodeRequest(MFA_SMS, "123456", JourneyType.REAUTHENTICATION, null);

        var response =
                makeRequest(
                        Optional.of(codeRequest),
                        constructFrontendHeaders(sessionId, CLIENT_SESSION_ID),
                        Map.of());

        assertThat(response, hasStatus(400));
        assertThat(response, hasJsonBody(ErrorResponse.INVALID_MFA_CODE_ENTERED));
        assertThat(
                authSessionExtension.getSession(sessionId).get().getVerifiedMfaMethodType(),
                equalTo(null));
    }

    @ParameterizedTest
    @MethodSource("journeyTypes")
    void shouldReturn204WhenUserEntersValidMfaSmsCode(JourneyType journeyType) {
        var internalCommonSubjectId =
                ClientSubjectHelper.calculatePairwiseIdentifier(
                        SUBJECT.getValue(), INTERNAl_SECTOR_HOST, SaltHelper.generateNewSalt());
        authSessionExtension.addInternalCommonSubjectIdToSession(
                this.sessionId, internalCommonSubjectId);
        setUpTestWithoutSignUp(sessionId);
        userStore.signUp(EMAIL_ADDRESS, "password", SUBJECT);
        userStore.addVerifiedPhoneNumber(EMAIL_ADDRESS, PHONE_NUMBER);
        userStore.updateTermsAndConditions(EMAIL_ADDRESS, "1.0");

        var code = redis.generateAndSaveMfaCode(EMAIL_ADDRESS.concat(PHONE_NUMBER), 900);
        var codeRequest = new VerifyCodeRequest(NotificationType.MFA_SMS, code, journeyType, null);

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

    private static Stream<MFAMethod> chosenMethods() {
        return Stream.of(DEFAULT_SMS_METHOD, BACKUP_SMS_METHOD);
    }

    @ParameterizedTest
    @MethodSource("chosenMethods")
    void shouldReturn204WhenUserChoosesIdentifiedMfaMethod(MFAMethod chosenMethod)
            throws Exception {
        var internalCommonSubjectId =
                ClientSubjectHelper.calculatePairwiseIdentifier(
                        SUBJECT.getValue(), INTERNAl_SECTOR_HOST, SaltHelper.generateNewSalt());
        authSessionExtension.addInternalCommonSubjectIdToSession(
                this.sessionId, internalCommonSubjectId);
        setUpTestWithoutSignUp(sessionId);
        userStore.signUp(EMAIL_ADDRESS, "password", SUBJECT);
        userStore.addMfaMethodSupportingMultiple(EMAIL_ADDRESS, DEFAULT_SMS_METHOD);
        userStore.addMfaMethodSupportingMultiple(EMAIL_ADDRESS, BACKUP_SMS_METHOD);
        userStore.setMfaMethodsMigrated(EMAIL_ADDRESS, true);
        userStore.updateTermsAndConditions(EMAIL_ADDRESS, "1.0");

        var code =
                redis.generateAndSaveMfaCode(
                        EMAIL_ADDRESS.concat(chosenMethod.getDestination()), 900);
        var codeRequest =
                new VerifyCodeRequest(
                        NotificationType.MFA_SMS,
                        code,
                        JourneyType.SIGN_IN,
                        chosenMethod.getMfaIdentifier());

        var response =
                makeRequest(
                        Optional.of(codeRequest),
                        constructFrontendHeaders(sessionId, CLIENT_SESSION_ID),
                        Map.of());

        assertThat(response, hasStatus(204));
    }

    @ParameterizedTest
    @MethodSource("journeyTypes")
    void shouldReturn204WhenUserEntersValidMfaSmsCodeAndClearAccountRecoveryBlockWhenPresent(
            JourneyType journeyType) {
        var internalCommonSubjectId =
                ClientSubjectHelper.calculatePairwiseIdentifier(
                        SUBJECT.getValue(), INTERNAl_SECTOR_HOST, SaltHelper.generateNewSalt());
        accountModifiersStore.setAccountRecoveryBlock(internalCommonSubjectId);
        authSessionExtension.addInternalCommonSubjectIdToSession(
                this.sessionId, internalCommonSubjectId);
        setUpTestWithoutSignUp(sessionId);
        userStore.signUp(EMAIL_ADDRESS, "password", SUBJECT);
        userStore.addVerifiedPhoneNumber(EMAIL_ADDRESS, PHONE_NUMBER);
        userStore.updateTermsAndConditions(EMAIL_ADDRESS, "1.0");

        var code = redis.generateAndSaveMfaCode(EMAIL_ADDRESS.concat(PHONE_NUMBER), 900);
        var codeRequest = new VerifyCodeRequest(NotificationType.MFA_SMS, code, journeyType, null);

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
    void shouldReturn204WhenUserEntersValidMfaSmsCodeAndSessionCommonSubjectIdNotPresent() {
        setUpTestWithoutSignUp(sessionId);
        userStore.signUp(EMAIL_ADDRESS, "password", SUBJECT);
        userStore.addVerifiedPhoneNumber(EMAIL_ADDRESS, PHONE_NUMBER);
        userStore.updateTermsAndConditions(EMAIL_ADDRESS, "1.0");

        var code = redis.generateAndSaveMfaCode(EMAIL_ADDRESS.concat(PHONE_NUMBER), 900);
        var codeRequest =
                new VerifyCodeRequest(
                        NotificationType.MFA_SMS, code, JourneyType.PASSWORD_RESET_MFA, null);

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
            JourneyType journeyType) {
        var internalCommonSubjectId =
                ClientSubjectHelper.calculatePairwiseIdentifier(
                        SUBJECT.getValue(), INTERNAl_SECTOR_HOST, SaltHelper.generateNewSalt());
        accountModifiersStore.setAccountRecoveryBlock(internalCommonSubjectId);
        authSessionExtension.addInternalCommonSubjectIdToSession(
                this.sessionId, internalCommonSubjectId);
        setUpTestWithSignUp(sessionId);
        userStore.addVerifiedPhoneNumber(EMAIL_ADDRESS, PHONE_NUMBER);
        userStore.updateTermsAndConditions(EMAIL_ADDRESS, "1.0");

        redis.generateAndSaveMfaCode(EMAIL_ADDRESS.concat(PHONE_NUMBER).concat("123123"), 900);
        var codeRequest =
                new VerifyCodeRequest(NotificationType.MFA_SMS, "123456", journeyType, null);

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

    private void setUpTestWithoutSignUp(String sessionId) {
        authSessionExtension.addEmailToSession(sessionId, EMAIL_ADDRESS);
    }

    private void setUpTestWithSignUp(String sessionId) {
        setUpTestWithoutSignUp(sessionId);
        userStore.signUp(EMAIL_ADDRESS, "password");
    }
}
