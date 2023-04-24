package uk.gov.di.authentication.api;

import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.authentication.frontendapi.entity.VerifyMfaCodeRequest;
import uk.gov.di.authentication.frontendapi.lambda.VerifyMfaCodeHandler;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.MFAMethodType;
import uk.gov.di.authentication.shared.entity.ServiceType;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;
import uk.gov.di.authentication.sharedtest.helper.AuthAppStub;

import java.net.URI;
import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Stream;

import static java.util.Collections.singletonList;
import static org.awaitility.Awaitility.await;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.CODE_MAX_RETRIES_REACHED;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.CODE_VERIFIED;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.INVALID_CODE_SENT;
import static uk.gov.di.authentication.sharedtest.helper.AuditAssertionsHelper.assertTxmaAuditEventsReceived;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class VerifyMfaCodeIntegrationTest extends ApiGatewayHandlerIntegrationTest {
    private static final String EMAIL_ADDRESS = "test@test.com";
    private static final String USER_PASSWORD = "TestPassword123!";
    private static final String CLIENT_ID = "test-client-id";
    private static final String REDIRECT_URI = "http://localhost/redirect";
    public static final String CLIENT_SESSION_ID = "a-client-session-id";
    private static final String AUTH_APP_SECRET_BASE_32 = "ORSXG5BNORSXQ5A=";
    private static final String PHONE_NUMBER = "+447700900000";
    private static final AuthAppStub AUTH_APP_STUB = new AuthAppStub();
    private static final String CLIENT_NAME = "test-client-name";
    private String sessionId;

    @BeforeEach
    void beforeEachSetup() throws Json.JsonException {
        handler = new VerifyMfaCodeHandler(TXMA_ENABLED_CONFIGURATION_SERVICE);

        txmaAuditQueue.clear();

        this.sessionId = redis.createSession();
        setUpTest(sessionId, withScope());
    }

    private static Stream<Arguments> verifyMfaCodeRequest() {
        return Stream.of(Arguments.of(true, AUTH_APP_SECRET_BASE_32), Arguments.of(false, null));
    }

    @ParameterizedTest
    @MethodSource("verifyMfaCodeRequest")
    void whenValidAuthAppOtpCodeReturn204(
            boolean isRegistrationRequest, String profileInformation) {
        setUpAuthAppRequest(isRegistrationRequest);
        var code = AUTH_APP_STUB.getAuthAppOneTimeCode(AUTH_APP_SECRET_BASE_32);
        var codeRequest =
                new VerifyMfaCodeRequest(
                        MFAMethodType.AUTH_APP, code, isRegistrationRequest, profileInformation);

        var response =
                makeRequest(
                        Optional.of(codeRequest),
                        constructFrontendHeaders(sessionId, CLIENT_SESSION_ID),
                        Map.of());
        assertThat(response, hasStatus(204));

        assertTxmaAuditEventsReceived(txmaAuditQueue, singletonList(CODE_VERIFIED));
        assertThat(accountRecoveryStore.isBlockPresent(EMAIL_ADDRESS), equalTo(false));
        assertThat(userStore.isAccountVerified(EMAIL_ADDRESS), equalTo(true));
        assertThat(userStore.isAuthAppVerified(EMAIL_ADDRESS), equalTo(true));
    }

    @Test
    void shouldReturn204WhenSuccessfulAuthAppOtpCodeRegistrationRequestAndSetMfaMethod() {
        var secret = "JZ5PYIOWNZDAOBA65S5T77FEEKYCCIT2VE4RQDAJD7SO73T3LODA";
        var code = AUTH_APP_STUB.getAuthAppOneTimeCode(secret);
        var codeRequest = new VerifyMfaCodeRequest(MFAMethodType.AUTH_APP, code, true, secret);
        var response =
                makeRequest(
                        Optional.of(codeRequest),
                        constructFrontendHeaders(sessionId, CLIENT_SESSION_ID),
                        Map.of());
        assertThat(response, hasStatus(204));

        assertTxmaAuditEventsReceived(txmaAuditQueue, singletonList(CODE_VERIFIED));
        assertThat(accountRecoveryStore.isBlockPresent(EMAIL_ADDRESS), equalTo(false));
        assertThat(userStore.isAccountVerified(EMAIL_ADDRESS), equalTo(true));

        var mfaMethod = userStore.getMfaMethod(EMAIL_ADDRESS);
        assertTrue(
                mfaMethod.stream()
                        .filter(t -> t.getMfaMethodType().equals(MFAMethodType.AUTH_APP.getValue()))
                        .anyMatch(
                                t ->
                                        t.getCredentialValue().equals(secret)
                                                && t.isMethodVerified()));
    }

    @Test
    void shouldReturn400WhenAuthAppSecretIsInvalid() {
        var secret = "not-base-32-encoded-secret";
        var code = AUTH_APP_STUB.getAuthAppOneTimeCode(secret);
        var codeRequest = new VerifyMfaCodeRequest(MFAMethodType.AUTH_APP, code, true, secret);
        var response =
                makeRequest(
                        Optional.of(codeRequest),
                        constructFrontendHeaders(sessionId, CLIENT_SESSION_ID),
                        Map.of());

        assertThat(response, hasStatus(400));
        assertThat(response, hasJsonBody(ErrorResponse.ERROR_1041));
        assertThat(accountRecoveryStore.isBlockPresent(EMAIL_ADDRESS), equalTo(false));
        assertThat(userStore.isAccountVerified(EMAIL_ADDRESS), equalTo(false));
        assertTrue(Objects.isNull(userStore.getMfaMethod(EMAIL_ADDRESS)));
    }

    @Test
    void
            shouldReturn204WhenSuccessfulAuthAppOtpCodeRegistrationRequestAndOverwriteExistingMfaMethod() {
        var currentAuthAppCredential = "JZ5PYIOWNZDAOBA65S5T77FEEKYCCIT2VE4RQDAJD7SO73T3UYTS";
        var newAuthAppCredential = "JZ5PYIOWNZDAOBA65S5T77FEEKYCCIT2VE4RQDAJD7SO73T3LODA";

        userStore.addMfaMethod(
                EMAIL_ADDRESS, MFAMethodType.AUTH_APP, true, false, currentAuthAppCredential);
        var code = AUTH_APP_STUB.getAuthAppOneTimeCode(newAuthAppCredential);
        var codeRequest =
                new VerifyMfaCodeRequest(MFAMethodType.AUTH_APP, code, true, newAuthAppCredential);
        var response =
                makeRequest(
                        Optional.of(codeRequest),
                        constructFrontendHeaders(sessionId, CLIENT_SESSION_ID),
                        Map.of());
        assertThat(response, hasStatus(204));

        assertTxmaAuditEventsReceived(txmaAuditQueue, singletonList(CODE_VERIFIED));
        assertThat(accountRecoveryStore.isBlockPresent(EMAIL_ADDRESS), equalTo(false));
        assertThat(userStore.isAccountVerified(EMAIL_ADDRESS), equalTo(true));

        var mfaMethod = userStore.getMfaMethod(EMAIL_ADDRESS);
        assertTrue(
                mfaMethod.stream()
                        .filter(t -> t.getMfaMethodType().equals(MFAMethodType.AUTH_APP.getValue()))
                        .noneMatch(t -> t.getCredentialValue().equals(currentAuthAppCredential)));
        assertTrue(
                mfaMethod.stream()
                        .filter(t -> t.getMfaMethodType().equals(MFAMethodType.AUTH_APP.getValue()))
                        .anyMatch(
                                t ->
                                        t.getCredentialValue().equals(newAuthAppCredential)
                                                && t.isMethodVerified()));
    }

    @ParameterizedTest
    @MethodSource("verifyMfaCodeRequest")
    void whenValidAuthAppOtpCodeReturn204AndClearAccountRecoveryBlockWhenPresent(
            boolean isRegistrationRequest, String profileInformation) {
        accountRecoveryStore.addBlockWithoutTTL(EMAIL_ADDRESS);
        setUpAuthAppRequest(isRegistrationRequest);
        var code = AUTH_APP_STUB.getAuthAppOneTimeCode(AUTH_APP_SECRET_BASE_32);
        var codeRequest =
                new VerifyMfaCodeRequest(
                        MFAMethodType.AUTH_APP, code, isRegistrationRequest, profileInformation);

        var response =
                makeRequest(
                        Optional.of(codeRequest),
                        constructFrontendHeaders(sessionId, CLIENT_SESSION_ID),
                        Map.of());
        assertThat(response, hasStatus(204));

        assertTxmaAuditEventsReceived(txmaAuditQueue, singletonList(CODE_VERIFIED));
        assertThat(accountRecoveryStore.isBlockPresent(EMAIL_ADDRESS), equalTo(false));
        assertThat(userStore.isAccountVerified(EMAIL_ADDRESS), equalTo(true));
        assertThat(userStore.isAuthAppVerified(EMAIL_ADDRESS), equalTo(true));
    }

    @ParameterizedTest
    @MethodSource("verifyMfaCodeRequest")
    void whenTwoMinuteOldValidAuthAppOtpCodeReturn204(
            boolean isRegistrationRequest, String profileInformation) {
        setUpAuthAppRequest(isRegistrationRequest);
        long oneMinuteAgo = NowHelper.nowMinus(2, ChronoUnit.MINUTES).getTime();
        var code = AUTH_APP_STUB.getAuthAppOneTimeCode(AUTH_APP_SECRET_BASE_32, oneMinuteAgo);
        var codeRequest =
                new VerifyMfaCodeRequest(
                        MFAMethodType.AUTH_APP, code, isRegistrationRequest, profileInformation);

        var response =
                makeRequest(
                        Optional.of(codeRequest),
                        constructFrontendHeaders(sessionId, CLIENT_SESSION_ID),
                        Map.of());

        assertThat(response, hasStatus(204));
        assertTxmaAuditEventsReceived(txmaAuditQueue, singletonList(CODE_VERIFIED));
        assertThat(userStore.isAccountVerified(EMAIL_ADDRESS), equalTo(true));
        assertThat(userStore.isAuthAppVerified(EMAIL_ADDRESS), equalTo(true));
    }

    @ParameterizedTest
    @MethodSource("verifyMfaCodeRequest")
    void whenFiveMinuteOldAuthAppOtpCodeReturn400(
            boolean isRegistrationRequest, String profileInformation) {
        setUpAuthAppRequest(isRegistrationRequest);
        long tenMinutesAgo = NowHelper.nowMinus(5, ChronoUnit.MINUTES).getTime();
        String code = AUTH_APP_STUB.getAuthAppOneTimeCode(AUTH_APP_SECRET_BASE_32, tenMinutesAgo);
        VerifyMfaCodeRequest codeRequest =
                new VerifyMfaCodeRequest(
                        MFAMethodType.AUTH_APP, code, isRegistrationRequest, profileInformation);

        var response =
                makeRequest(
                        Optional.of(codeRequest),
                        constructFrontendHeaders(sessionId, CLIENT_SESSION_ID),
                        Map.of());

        assertThat(response, hasStatus(400));
        assertTxmaAuditEventsReceived(txmaAuditQueue, singletonList(INVALID_CODE_SENT));
        assertThat(
                userStore.isAccountVerified(EMAIL_ADDRESS), equalTo(!codeRequest.isRegistration()));
        assertThat(
                userStore.isAuthAppVerified(EMAIL_ADDRESS), equalTo(!codeRequest.isRegistration()));
    }

    @ParameterizedTest
    @MethodSource("verifyMfaCodeRequest")
    void whenWrongSecretUsedByAuthAppReturn400(
            boolean isRegistrationRequest, String profileInformation) {
        setUpAuthAppRequest(isRegistrationRequest);
        String invalidCode = AUTH_APP_STUB.getAuthAppOneTimeCode("O5ZG63THFVZWKY3SMV2A====");
        VerifyMfaCodeRequest codeRequest =
                new VerifyMfaCodeRequest(
                        MFAMethodType.AUTH_APP,
                        invalidCode,
                        isRegistrationRequest,
                        profileInformation);

        var response =
                makeRequest(
                        Optional.of(codeRequest),
                        constructFrontendHeaders(sessionId, CLIENT_SESSION_ID),
                        Map.of());

        assertThat(response, hasStatus(400));
        assertThat(response, hasJsonBody(ErrorResponse.ERROR_1043));
        assertTxmaAuditEventsReceived(txmaAuditQueue, singletonList(INVALID_CODE_SENT));
        assertThat(userStore.isAccountVerified(EMAIL_ADDRESS), equalTo(!isRegistrationRequest));
        assertThat(userStore.isAuthAppVerified(EMAIL_ADDRESS), equalTo(!isRegistrationRequest));
    }

    @Test
    void whenWrongSecretUsedByAuthAppReturn400AndNotClearAccountRecoveryBlockWhenPresent() {
        accountRecoveryStore.addBlockWithoutTTL(EMAIL_ADDRESS);
        setUpAuthAppRequest(false);
        String invalidCode = AUTH_APP_STUB.getAuthAppOneTimeCode("O5ZG63THFVZWKY3SMV2A====");
        VerifyMfaCodeRequest codeRequest =
                new VerifyMfaCodeRequest(MFAMethodType.AUTH_APP, invalidCode, false, null);

        var response =
                makeRequest(
                        Optional.of(codeRequest),
                        constructFrontendHeaders(sessionId, CLIENT_SESSION_ID),
                        Map.of());

        assertThat(response, hasStatus(400));
        assertThat(response, hasJsonBody(ErrorResponse.ERROR_1043));
        assertTxmaAuditEventsReceived(txmaAuditQueue, singletonList(INVALID_CODE_SENT));
        assertThat(accountRecoveryStore.isBlockPresent(EMAIL_ADDRESS), equalTo(true));
        assertThat(userStore.isAccountVerified(EMAIL_ADDRESS), equalTo(true));
        assertThat(userStore.isAuthAppVerified(EMAIL_ADDRESS), equalTo(true));
    }

    @Test
    void whenAuthAppMfaMethodIsNotEnabledReturn400() {
        userStore.addMfaMethod(
                EMAIL_ADDRESS, MFAMethodType.AUTH_APP, true, false, AUTH_APP_SECRET_BASE_32);
        String code = AUTH_APP_STUB.getAuthAppOneTimeCode(AUTH_APP_SECRET_BASE_32);
        VerifyMfaCodeRequest codeRequest =
                new VerifyMfaCodeRequest(MFAMethodType.AUTH_APP, code, true);

        var response =
                makeRequest(
                        Optional.of(codeRequest),
                        constructFrontendHeaders(sessionId, CLIENT_SESSION_ID),
                        Map.of());

        assertThat(response, hasStatus(400));
        assertThat(response, hasJsonBody(ErrorResponse.ERROR_1043));
        assertTxmaAuditEventsReceived(txmaAuditQueue, singletonList(INVALID_CODE_SENT));
    }

    @Test
    void whenParametersMissingReturn400() {
        userStore.addMfaMethod(
                EMAIL_ADDRESS, MFAMethodType.AUTH_APP, true, true, AUTH_APP_SECRET_BASE_32);
        String code = AUTH_APP_STUB.getAuthAppOneTimeCode(AUTH_APP_SECRET_BASE_32);
        VerifyMfaCodeRequest codeRequest = new VerifyMfaCodeRequest(null, code, true);

        var response =
                makeRequest(
                        Optional.of(codeRequest),
                        constructFrontendHeaders(sessionId, CLIENT_SESSION_ID),
                        Map.of());

        assertThat(response, hasStatus(400));
        assertThat(response, hasJsonBody(ErrorResponse.ERROR_1001));
    }

    @ParameterizedTest
    @MethodSource("verifyMfaCodeRequest")
    void whenAuthAppCodeSubmissionBlockedReturn400(boolean isRegistrationRequest) {
        setUpAuthAppRequest(isRegistrationRequest);
        String code = AUTH_APP_STUB.getAuthAppOneTimeCode(AUTH_APP_SECRET_BASE_32);
        VerifyMfaCodeRequest codeRequest =
                new VerifyMfaCodeRequest(MFAMethodType.AUTH_APP, code, isRegistrationRequest);

        redis.blockMfaCodesForEmail(EMAIL_ADDRESS);

        var response =
                makeRequest(
                        Optional.of(codeRequest),
                        constructFrontendHeaders(sessionId, CLIENT_SESSION_ID),
                        Map.of());

        assertThat(response, hasStatus(400));
        assertThat(response, hasJsonBody(ErrorResponse.ERROR_1042));
        assertTxmaAuditEventsReceived(txmaAuditQueue, singletonList(CODE_MAX_RETRIES_REACHED));
        assertThat(userStore.isAccountVerified(EMAIL_ADDRESS), equalTo(!isRegistrationRequest));
        assertThat(userStore.isAuthAppVerified(EMAIL_ADDRESS), equalTo(!isRegistrationRequest));
    }

    @Test
    void whenAuthAppCodeRetriesLimitExceededForSignInBlockEmailAndReturn400()
            throws Json.JsonException {
        setUpAuthAppRequest(false);
        String invalidCode = AUTH_APP_STUB.getAuthAppOneTimeCode("O5ZG63THFVZWKY3SMV2A====");
        VerifyMfaCodeRequest codeRequest =
                new VerifyMfaCodeRequest(MFAMethodType.AUTH_APP, invalidCode, false);

        for (int i = 0; i < 5; i++) {
            redis.increaseMfaCodeAttemptsCount(EMAIL_ADDRESS, MFAMethodType.AUTH_APP);
        }

        assertEquals(5, redis.getMfaCodeAttemptsCount(EMAIL_ADDRESS, MFAMethodType.AUTH_APP));

        var response =
                makeRequest(
                        Optional.of(codeRequest),
                        constructFrontendHeaders(sessionId, CLIENT_SESSION_ID),
                        Map.of());

        assertThat(response, hasStatus(400));
        assertThat(response, hasJsonBody(ErrorResponse.ERROR_1042));
        assertEquals(0, redis.getMfaCodeAttemptsCount(EMAIL_ADDRESS, MFAMethodType.AUTH_APP));
        assertTrue(redis.isBlockedMfaCodesForEmail(EMAIL_ADDRESS));
        assertTrue(userStore.isAccountVerified(EMAIL_ADDRESS));
        assertTrue(userStore.isAuthAppVerified(EMAIL_ADDRESS));
    }

    @Test
    void
            whenIncorrectAuthCodesInputtedUpToSmsRetriesLimitAllowSmsAttemptAndReturn400WithoutBlockingFurtherRetries()
                    throws Json.JsonException {
        for (int i = 0; i < 5; i++) {
            redis.increaseMfaCodeAttemptsCount(EMAIL_ADDRESS, MFAMethodType.AUTH_APP);
        }

        String invalidCode = "999999";
        VerifyMfaCodeRequest codeRequest =
                new VerifyMfaCodeRequest(MFAMethodType.SMS, invalidCode, true);

        var response =
                makeRequest(
                        Optional.of(codeRequest),
                        constructFrontendHeaders(sessionId, CLIENT_SESSION_ID),
                        Map.of());

        assertThat(response, hasStatus(400));
        assertThat(response, hasJsonBody(ErrorResponse.ERROR_1037));
        assertEquals(1, redis.getMfaCodeAttemptsCount(EMAIL_ADDRESS));
        assertFalse(redis.isBlockedMfaCodesForEmail(EMAIL_ADDRESS));
    }

    @Test
    void whenValidPhoneNumberOtpCodeForRegistrationReturn204AndUpdatePhoneNumber() {
        var code = redis.generateAndSavePhoneNumberCode(EMAIL_ADDRESS, 900);
        var codeRequest = new VerifyMfaCodeRequest(MFAMethodType.SMS, code, true, PHONE_NUMBER);

        var response =
                makeRequest(
                        Optional.of(codeRequest),
                        constructFrontendHeaders(sessionId, CLIENT_SESSION_ID),
                        Map.of());

        assertThat(response, hasStatus(204));
        assertTxmaAuditEventsReceived(txmaAuditQueue, List.of(CODE_VERIFIED));
        assertThat(userStore.isAccountVerified(EMAIL_ADDRESS), equalTo(true));
        assertThat(userStore.getPhoneNumberForUser(EMAIL_ADDRESS).get(), equalTo(PHONE_NUMBER));
        assertTrue(userStore.isPhoneNumberVerified(EMAIL_ADDRESS));
    }

    @Test
    void shouldReturn204WhenSuccessfulSMSRegistrationRequestAndOverwriteExistingPhoneNumber() {
        userStore.addPhoneNumber(EMAIL_ADDRESS, "+447700900111");
        var code = redis.generateAndSavePhoneNumberCode(EMAIL_ADDRESS, 900);
        var codeRequest = new VerifyMfaCodeRequest(MFAMethodType.SMS, code, true, PHONE_NUMBER);

        var response =
                makeRequest(
                        Optional.of(codeRequest),
                        constructFrontendHeaders(sessionId, CLIENT_SESSION_ID),
                        Map.of());

        assertThat(response, hasStatus(204));
        assertTxmaAuditEventsReceived(txmaAuditQueue, List.of(CODE_VERIFIED));
        assertThat(userStore.isAccountVerified(EMAIL_ADDRESS), equalTo(true));
        assertThat(userStore.getPhoneNumberForUser(EMAIL_ADDRESS).get(), equalTo(PHONE_NUMBER));
        assertTrue(userStore.isPhoneNumberVerified(EMAIL_ADDRESS));
    }

    @Test
    void whenValidPhoneNumberCodeForRegistrationReturn204AndInvalidateAuthApp() {
        userStore.addMfaMethod(
                EMAIL_ADDRESS, MFAMethodType.AUTH_APP, false, true, AUTH_APP_SECRET_BASE_32);
        var code = redis.generateAndSavePhoneNumberCode(EMAIL_ADDRESS, 900);
        var codeRequest = new VerifyMfaCodeRequest(MFAMethodType.SMS, code, true, PHONE_NUMBER);

        var response =
                makeRequest(
                        Optional.of(codeRequest),
                        constructFrontendHeaders(sessionId, CLIENT_SESSION_ID),
                        Map.of());

        assertThat(response, hasStatus(204));
        assertTxmaAuditEventsReceived(txmaAuditQueue, List.of(CODE_VERIFIED));
        assertThat(userStore.isAuthAppEnabled(EMAIL_ADDRESS), equalTo(false));
        assertThat(userStore.isAccountVerified(EMAIL_ADDRESS), equalTo(true));
        assertThat(userStore.getPhoneNumberForUser(EMAIL_ADDRESS).get(), equalTo(PHONE_NUMBER));
        assertTrue(userStore.isPhoneNumberVerified(EMAIL_ADDRESS));
    }

    @Test
    void whenInvalidPhoneNumberCodeHasExpiredForRegistrationReturn400() {
        var code = redis.generateAndSavePhoneNumberCode(EMAIL_ADDRESS, 1);
        var codeRequest = new VerifyMfaCodeRequest(MFAMethodType.SMS, code, true);

        await().pollDelay(Duration.ofSeconds(2)).untilAsserted(() -> assertTrue(true));

        var response =
                makeRequest(
                        Optional.of(codeRequest),
                        constructFrontendHeaders(sessionId, CLIENT_SESSION_ID),
                        Map.of());

        assertThat(response, hasStatus(400));
        assertThat(response, hasJsonBody(ErrorResponse.ERROR_1037));
        assertTxmaAuditEventsReceived(txmaAuditQueue, List.of(INVALID_CODE_SENT));
    }

    @Test
    void whenInvalidPhoneNumberCodeForRegistrationReturn400() {
        var codeRequest = new VerifyMfaCodeRequest(MFAMethodType.SMS, "123456", true);

        var response =
                makeRequest(
                        Optional.of(codeRequest),
                        constructFrontendHeaders(sessionId, CLIENT_SESSION_ID),
                        Map.of());

        assertThat(response, hasStatus(400));
        assertThat(response, hasJsonBody(ErrorResponse.ERROR_1037));
        assertTxmaAuditEventsReceived(txmaAuditQueue, List.of(INVALID_CODE_SENT));
    }

    @Test
    void whenPhoneNumberCodeIsBlockedForRegistrationReturn400() throws Json.JsonException {
        redis.addEmailToSession(sessionId, EMAIL_ADDRESS);
        redis.blockMfaCodesForEmail(EMAIL_ADDRESS);

        var codeRequest = new VerifyMfaCodeRequest(MFAMethodType.SMS, "123456", true);

        var response =
                makeRequest(
                        Optional.of(codeRequest), constructFrontendHeaders(sessionId), Map.of());

        assertThat(response, hasStatus(400));
        assertThat(response, hasJsonBody(ErrorResponse.ERROR_1034));
        assertTxmaAuditEventsReceived(txmaAuditQueue, singletonList(CODE_MAX_RETRIES_REACHED));
    }

    @Test
    void whenPhoneNumberCodeRetriesLimitExceededForRegistrationBlockEmailAndReturn400()
            throws Json.JsonException {
        redis.addEmailToSession(sessionId, EMAIL_ADDRESS);

        var codeRequest = new VerifyMfaCodeRequest(MFAMethodType.SMS, "123456", true);

        for (int i = 0; i < 5; i++) {
            makeRequest(
                    Optional.of(codeRequest),
                    constructFrontendHeaders(sessionId, CLIENT_SESSION_ID),
                    Map.of());
        }

        var response =
                makeRequest(
                        Optional.of(codeRequest), constructFrontendHeaders(sessionId), Map.of());

        assertThat(response, hasStatus(400));
        assertThat(response, hasJsonBody(ErrorResponse.ERROR_1034));
        assertTxmaAuditEventsReceived(
                txmaAuditQueue,
                List.of(
                        INVALID_CODE_SENT,
                        INVALID_CODE_SENT,
                        INVALID_CODE_SENT,
                        INVALID_CODE_SENT,
                        INVALID_CODE_SENT,
                        CODE_MAX_RETRIES_REACHED));
    }

    private void setUpTest(String sessionId, Scope scope) throws Json.JsonException {
        userStore.signUp(EMAIL_ADDRESS, USER_PASSWORD);
        redis.addEmailToSession(sessionId, EMAIL_ADDRESS);
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
                "https://example.com",
                String.valueOf(ServiceType.MANDATORY),
                "https://test.com",
                "public",
                true);
    }

    private Scope withScope() {
        Scope scope = new Scope();
        scope.add(OIDCScopeValue.OPENID);
        scope.add(OIDCScopeValue.EMAIL);
        return scope;
    }

    public void setUpAuthAppRequest(boolean isRegistrationRequest) {
        if (!isRegistrationRequest) {
            userStore.setAccountVerified(EMAIL_ADDRESS);
            userStore.addMfaMethod(
                    EMAIL_ADDRESS, MFAMethodType.AUTH_APP, true, true, AUTH_APP_SECRET_BASE_32);
        }
    }
}
