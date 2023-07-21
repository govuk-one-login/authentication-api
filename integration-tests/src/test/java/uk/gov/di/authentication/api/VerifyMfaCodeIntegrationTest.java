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
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import uk.gov.di.authentication.entity.VerifyMfaCodeRequest;
import uk.gov.di.authentication.frontendapi.lambda.VerifyMfaCodeHandler;
import uk.gov.di.authentication.shared.domain.AuditableEvent;
import uk.gov.di.authentication.shared.entity.CodeRequestType;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.MFAMethodType;
import uk.gov.di.authentication.shared.entity.NotificationType;
import uk.gov.di.authentication.shared.entity.ServiceType;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.helpers.SaltHelper;
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
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.ACCOUNT_RECOVERY_BLOCK_REMOVED;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.CODE_MAX_RETRIES_REACHED;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.CODE_VERIFIED;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.INVALID_CODE_SENT;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.UPDATE_PROFILE_AUTH_APP;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.UPDATE_PROFILE_PHONE_NUMBER;
import static uk.gov.di.authentication.shared.services.CodeStorageService.CODE_BLOCKED_KEY_PREFIX;
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
    private static final String ALTERNATIVE_AUTH_APP_SECRET_BASE_32 =
            "JZ5PYIOWNZDAOBA65S5T77FEEKYCCIT2VE4RQDAJD7SO73T3LODA";
    private static final String PHONE_NUMBER = "+447700900000";
    private static final String ALTERNATIVE_PHONE_NUMBER = "+447316763843";
    private static final AuthAppStub AUTH_APP_STUB = new AuthAppStub();
    private static final Subject SUBJECT = new Subject();
    private static final String INTERNAl_SECTOR_HOST = "test.account.gov.uk";
    private static final String CLIENT_NAME = "test-client-name";
    private final String internalCommonSubjectId =
            ClientSubjectHelper.calculatePairwiseIdentifier(
                    SUBJECT.getValue(), INTERNAl_SECTOR_HOST, SaltHelper.generateNewSalt());
    private String sessionId;

    @BeforeEach
    void beforeEachSetup() throws Json.JsonException {
        handler = new VerifyMfaCodeHandler(TXMA_ENABLED_CONFIGURATION_SERVICE);

        txmaAuditQueue.clear();

        this.sessionId = redis.createSession();
        redis.addInternalCommonSubjectIdToSession(this.sessionId, internalCommonSubjectId);
        setUpTest(sessionId, withScope());
    }

    private static Stream<Arguments> verifyMfaCodeRequest() {
        return Stream.of(
                Arguments.of(JourneyType.REGISTRATION, ALTERNATIVE_AUTH_APP_SECRET_BASE_32),
                Arguments.of(JourneyType.ACCOUNT_RECOVERY, ALTERNATIVE_AUTH_APP_SECRET_BASE_32),
                Arguments.of(JourneyType.SIGN_IN, null));
    }

    @Test
    void whenValidAuthAppOtpCodeReturn204ForSignIn() {
        setUpAuthAppRequest(JourneyType.SIGN_IN);
        var code = AUTH_APP_STUB.getAuthAppOneTimeCode(AUTH_APP_SECRET_BASE_32);
        var codeRequest =
                new VerifyMfaCodeRequest(MFAMethodType.AUTH_APP, code, JourneyType.SIGN_IN);

        var response =
                makeRequest(
                        Optional.of(codeRequest),
                        constructFrontendHeaders(sessionId, CLIENT_SESSION_ID),
                        Map.of());
        assertThat(response, hasStatus(204));

        assertTxmaAuditEventsReceived(txmaAuditQueue, singletonList(CODE_VERIFIED));
        assertThat(accountModifiersStore.isBlockPresent(internalCommonSubjectId), equalTo(false));
        assertThat(userStore.isAccountVerified(EMAIL_ADDRESS), equalTo(true));
        assertThat(userStore.isAuthAppVerified(EMAIL_ADDRESS), equalTo(true));
    }

    @Test
    void whenValidAuthAppOtpRemovePhoneNumberWhenPresentAndSetAuthAppForAccountRecovery() {
        userStore.addVerifiedPhoneNumber(EMAIL_ADDRESS, PHONE_NUMBER);
        userStore.setAccountVerified(EMAIL_ADDRESS);
        var code = AUTH_APP_STUB.getAuthAppOneTimeCode(ALTERNATIVE_AUTH_APP_SECRET_BASE_32);
        var codeRequest =
                new VerifyMfaCodeRequest(
                        MFAMethodType.AUTH_APP,
                        code,
                        JourneyType.ACCOUNT_RECOVERY,
                        ALTERNATIVE_AUTH_APP_SECRET_BASE_32);

        var response =
                makeRequest(
                        Optional.of(codeRequest),
                        constructFrontendHeaders(sessionId, CLIENT_SESSION_ID),
                        Map.of());

        assertThat(response, hasStatus(204));

        assertTxmaAuditEventsReceived(
                txmaAuditQueue, List.of(CODE_VERIFIED, UPDATE_PROFILE_AUTH_APP));
        assertThat(accountModifiersStore.isBlockPresent(internalCommonSubjectId), equalTo(false));
        assertThat(userStore.isAccountVerified(EMAIL_ADDRESS), equalTo(true));
        assertThat(userStore.isAuthAppVerified(EMAIL_ADDRESS), equalTo(true));
        assertThat(
                userStore.getMfaMethod(EMAIL_ADDRESS).get(0).getCredentialValue(),
                equalTo(ALTERNATIVE_AUTH_APP_SECRET_BASE_32));
        assertThat(userStore.getPhoneNumberForUser(EMAIL_ADDRESS), equalTo(Optional.empty()));
        assertThat(userStore.isPhoneNumberVerified(EMAIL_ADDRESS), equalTo(false));
    }

    @Test
    void whenValidOtpRemoveExistingAuthAppAndSetAuthAppWhenAccountRecovery() {
        setUpAuthAppRequest(JourneyType.ACCOUNT_RECOVERY);
        var code = AUTH_APP_STUB.getAuthAppOneTimeCode(ALTERNATIVE_AUTH_APP_SECRET_BASE_32);
        var codeRequest =
                new VerifyMfaCodeRequest(
                        MFAMethodType.AUTH_APP,
                        code,
                        JourneyType.ACCOUNT_RECOVERY,
                        ALTERNATIVE_AUTH_APP_SECRET_BASE_32);

        var response =
                makeRequest(
                        Optional.of(codeRequest),
                        constructFrontendHeaders(sessionId, CLIENT_SESSION_ID),
                        Map.of());

        assertThat(response, hasStatus(204));
        assertTxmaAuditEventsReceived(
                txmaAuditQueue, List.of(CODE_VERIFIED, UPDATE_PROFILE_AUTH_APP));
        assertThat(accountModifiersStore.isBlockPresent(internalCommonSubjectId), equalTo(false));
        assertThat(userStore.isAccountVerified(EMAIL_ADDRESS), equalTo(true));
        assertThat(userStore.getMfaMethod(EMAIL_ADDRESS).size(), equalTo(1));
        assertThat(userStore.isAuthAppVerified(EMAIL_ADDRESS), equalTo(true));
        assertThat(
                userStore.getMfaMethod(EMAIL_ADDRESS).get(0).getCredentialValue(),
                equalTo(ALTERNATIVE_AUTH_APP_SECRET_BASE_32));
        assertThat(userStore.getPhoneNumberForUser(EMAIL_ADDRESS), equalTo(Optional.empty()));
        assertThat(userStore.isPhoneNumberVerified(EMAIL_ADDRESS), equalTo(false));
    }

    @Test
    void shouldReturn204WhenSuccessfulAuthAppOtpCodeRegistrationRequestAndSetMfaMethod() {
        var secret = "JZ5PYIOWNZDAOBA65S5T77FEEKYCCIT2VE4RQDAJD7SO73T3LODA";
        var code = AUTH_APP_STUB.getAuthAppOneTimeCode(secret);
        var codeRequest =
                new VerifyMfaCodeRequest(
                        MFAMethodType.AUTH_APP, code, JourneyType.REGISTRATION, secret);
        var response =
                makeRequest(
                        Optional.of(codeRequest),
                        constructFrontendHeaders(sessionId, CLIENT_SESSION_ID),
                        Map.of());
        assertThat(response, hasStatus(204));

        assertTxmaAuditEventsReceived(
                txmaAuditQueue, List.of(CODE_VERIFIED, UPDATE_PROFILE_AUTH_APP));
        assertThat(accountModifiersStore.isBlockPresent(internalCommonSubjectId), equalTo(false));
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
    void shouldReturn400WhenAuthAppSecretIsInvalidForRegistration() {
        var secret = "not-base-32-encoded-secret";
        var code = AUTH_APP_STUB.getAuthAppOneTimeCode(secret);
        var codeRequest =
                new VerifyMfaCodeRequest(
                        MFAMethodType.AUTH_APP, code, JourneyType.REGISTRATION, secret);
        var response =
                makeRequest(
                        Optional.of(codeRequest),
                        constructFrontendHeaders(sessionId, CLIENT_SESSION_ID),
                        Map.of());

        assertThat(response, hasStatus(400));
        assertThat(response, hasJsonBody(ErrorResponse.ERROR_1041));
        assertThat(accountModifiersStore.isBlockPresent(internalCommonSubjectId), equalTo(false));
        assertThat(userStore.isAccountVerified(EMAIL_ADDRESS), equalTo(false));
        assertTrue(Objects.isNull(userStore.getMfaMethod(EMAIL_ADDRESS)));
    }

    @Test
    void shouldReturn400AndNotAddAuthAppWhenAuthAppSecretIsInvalidForAccountRecovery() {
        setUpAuthAppRequest(JourneyType.ACCOUNT_RECOVERY);
        var secret = "not-base-32-encoded-secret";
        var code = AUTH_APP_STUB.getAuthAppOneTimeCode(secret);
        var codeRequest =
                new VerifyMfaCodeRequest(
                        MFAMethodType.AUTH_APP, code, JourneyType.ACCOUNT_RECOVERY, secret);
        var response =
                makeRequest(
                        Optional.of(codeRequest),
                        constructFrontendHeaders(sessionId, CLIENT_SESSION_ID),
                        Map.of());

        assertThat(response, hasStatus(400));
        assertThat(response, hasJsonBody(ErrorResponse.ERROR_1041));
        assertThat(accountModifiersStore.isBlockPresent(internalCommonSubjectId), equalTo(false));
        assertThat(userStore.isAccountVerified(EMAIL_ADDRESS), equalTo(true));
        assertThat(userStore.isAuthAppVerified(EMAIL_ADDRESS), equalTo(true));
        assertThat(userStore.getMfaMethod(EMAIL_ADDRESS).size(), equalTo(1));
        assertThat(
                userStore.getMfaMethod(EMAIL_ADDRESS).get(0).getCredentialValue(),
                equalTo(AUTH_APP_SECRET_BASE_32));
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
                new VerifyMfaCodeRequest(
                        MFAMethodType.AUTH_APP,
                        code,
                        JourneyType.REGISTRATION,
                        newAuthAppCredential);
        var response =
                makeRequest(
                        Optional.of(codeRequest),
                        constructFrontendHeaders(sessionId, CLIENT_SESSION_ID),
                        Map.of());
        assertThat(response, hasStatus(204));

        assertTxmaAuditEventsReceived(
                txmaAuditQueue, List.of(CODE_VERIFIED, UPDATE_PROFILE_AUTH_APP));
        assertThat(accountModifiersStore.isBlockPresent(internalCommonSubjectId), equalTo(false));
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

    @Test
    void whenValidAuthAppOtpReturn204AndClearAccountRecoveryBlockForSignIn() {
        accountModifiersStore.setAccountRecoveryBlock(internalCommonSubjectId);
        setUpAuthAppRequest(JourneyType.SIGN_IN);
        var code = AUTH_APP_STUB.getAuthAppOneTimeCode(AUTH_APP_SECRET_BASE_32);
        var codeRequest =
                new VerifyMfaCodeRequest(MFAMethodType.AUTH_APP, code, JourneyType.SIGN_IN);

        var response =
                makeRequest(
                        Optional.of(codeRequest),
                        constructFrontendHeaders(sessionId, CLIENT_SESSION_ID),
                        Map.of());
        assertThat(response, hasStatus(204));

        List<AuditableEvent> expectedAuditableEvents =
                List.of(CODE_VERIFIED, ACCOUNT_RECOVERY_BLOCK_REMOVED);
        assertTxmaAuditEventsReceived(txmaAuditQueue, expectedAuditableEvents);
        assertThat(accountModifiersStore.isBlockPresent(internalCommonSubjectId), equalTo(false));
        assertThat(userStore.isAccountVerified(EMAIL_ADDRESS), equalTo(true));
        assertThat(userStore.isAuthAppVerified(EMAIL_ADDRESS), equalTo(true));
    }

    @ParameterizedTest
    @MethodSource("verifyMfaCodeRequest")
    void whenTwoMinuteOldValidAuthAppOtpCodeReturn204(
            JourneyType journeyType, String profileInformation) {
        setUpAuthAppRequest(journeyType);
        var authAppSecret =
                journeyType.equals(JourneyType.SIGN_IN)
                        ? AUTH_APP_SECRET_BASE_32
                        : profileInformation;
        long oneMinuteAgo = NowHelper.nowMinus(2, ChronoUnit.MINUTES).getTime();
        var code = AUTH_APP_STUB.getAuthAppOneTimeCode(authAppSecret, oneMinuteAgo);
        var codeRequest =
                new VerifyMfaCodeRequest(
                        MFAMethodType.AUTH_APP, code, journeyType, profileInformation);

        var response =
                makeRequest(
                        Optional.of(codeRequest),
                        constructFrontendHeaders(sessionId, CLIENT_SESSION_ID),
                        Map.of());

        assertThat(response, hasStatus(204));
        List<AuditableEvent> expectedAuditableEvents =
                journeyType.equals(JourneyType.SIGN_IN)
                        ? singletonList(CODE_VERIFIED)
                        : List.of(CODE_VERIFIED, UPDATE_PROFILE_AUTH_APP);
        assertTxmaAuditEventsReceived(txmaAuditQueue, expectedAuditableEvents);
        assertThat(userStore.isAccountVerified(EMAIL_ADDRESS), equalTo(true));
        assertThat(userStore.isAuthAppVerified(EMAIL_ADDRESS), equalTo(true));
        assertThat(
                userStore.getMfaMethod(EMAIL_ADDRESS).get(0).getCredentialValue(),
                equalTo(authAppSecret));
    }

    @ParameterizedTest
    @MethodSource("verifyMfaCodeRequest")
    void whenFiveMinuteOldAuthAppOtpCodeReturn400(
            JourneyType journeyType, String profileInformation) {
        setUpAuthAppRequest(journeyType);
        var authAppSecret =
                journeyType.equals(JourneyType.SIGN_IN)
                        ? AUTH_APP_SECRET_BASE_32
                        : profileInformation;
        long tenMinutesAgo = NowHelper.nowMinus(5, ChronoUnit.MINUTES).getTime();
        String code = AUTH_APP_STUB.getAuthAppOneTimeCode(authAppSecret, tenMinutesAgo);
        VerifyMfaCodeRequest codeRequest =
                new VerifyMfaCodeRequest(
                        MFAMethodType.AUTH_APP, code, journeyType, profileInformation);

        var response =
                makeRequest(
                        Optional.of(codeRequest),
                        constructFrontendHeaders(sessionId, CLIENT_SESSION_ID),
                        Map.of());

        assertThat(response, hasStatus(400));
        assertTxmaAuditEventsReceived(txmaAuditQueue, singletonList(INVALID_CODE_SENT));
        var isAccountVerified =
                List.of(JourneyType.ACCOUNT_RECOVERY, JourneyType.SIGN_IN).contains(journeyType);
        assertThat(userStore.isAccountVerified(EMAIL_ADDRESS), equalTo(isAccountVerified));
        assertThat(userStore.isAuthAppVerified(EMAIL_ADDRESS), equalTo(isAccountVerified));
        if (isAccountVerified) {
            assertThat(
                    userStore.getMfaMethod(EMAIL_ADDRESS).get(0).getCredentialValue(),
                    equalTo(AUTH_APP_SECRET_BASE_32));
        }
    }

    @ParameterizedTest
    @MethodSource("verifyMfaCodeRequest")
    void whenWrongSecretUsedByAuthAppReturn400(JourneyType journeyType, String profileInformation) {
        setUpAuthAppRequest(journeyType);
        String invalidCode = AUTH_APP_STUB.getAuthAppOneTimeCode("O5ZG63THFVZWKY3SMV2A====");
        VerifyMfaCodeRequest codeRequest =
                new VerifyMfaCodeRequest(
                        MFAMethodType.AUTH_APP, invalidCode, journeyType, profileInformation);

        var response =
                makeRequest(
                        Optional.of(codeRequest),
                        constructFrontendHeaders(sessionId, CLIENT_SESSION_ID),
                        Map.of());

        var isAccountVerified =
                List.of(JourneyType.ACCOUNT_RECOVERY, JourneyType.SIGN_IN).contains(journeyType);
        assertThat(response, hasStatus(400));
        assertThat(response, hasJsonBody(ErrorResponse.ERROR_1043));
        assertTxmaAuditEventsReceived(txmaAuditQueue, singletonList(INVALID_CODE_SENT));
        assertThat(userStore.isAccountVerified(EMAIL_ADDRESS), equalTo(isAccountVerified));
        assertThat(userStore.isAuthAppVerified(EMAIL_ADDRESS), equalTo(isAccountVerified));
        if (isAccountVerified) {
            assertThat(
                    userStore.getMfaMethod(EMAIL_ADDRESS).get(0).getCredentialValue(),
                    equalTo(AUTH_APP_SECRET_BASE_32));
        }
    }

    @Test
    void whenWrongSecretUsedByAuthAppReturn400AndNotClearAccountRecoveryBlockWhenPresent() {
        accountModifiersStore.setAccountRecoveryBlock(internalCommonSubjectId);
        setUpAuthAppRequest(JourneyType.SIGN_IN);
        String invalidCode = AUTH_APP_STUB.getAuthAppOneTimeCode("O5ZG63THFVZWKY3SMV2A====");
        VerifyMfaCodeRequest codeRequest =
                new VerifyMfaCodeRequest(MFAMethodType.AUTH_APP, invalidCode, JourneyType.SIGN_IN);

        var response =
                makeRequest(
                        Optional.of(codeRequest),
                        constructFrontendHeaders(sessionId, CLIENT_SESSION_ID),
                        Map.of());

        assertThat(response, hasStatus(400));
        assertThat(response, hasJsonBody(ErrorResponse.ERROR_1043));
        assertTxmaAuditEventsReceived(txmaAuditQueue, singletonList(INVALID_CODE_SENT));
        assertThat(accountModifiersStore.isBlockPresent(internalCommonSubjectId), equalTo(true));
        assertThat(userStore.isAccountVerified(EMAIL_ADDRESS), equalTo(true));
        assertThat(userStore.isAuthAppVerified(EMAIL_ADDRESS), equalTo(true));
    }

    @Test
    void whenAuthAppMfaMethodIsNotEnabledReturn400() {
        userStore.addMfaMethod(
                EMAIL_ADDRESS, MFAMethodType.AUTH_APP, true, false, AUTH_APP_SECRET_BASE_32);
        String code = AUTH_APP_STUB.getAuthAppOneTimeCode(AUTH_APP_SECRET_BASE_32);
        VerifyMfaCodeRequest codeRequest =
                new VerifyMfaCodeRequest(MFAMethodType.AUTH_APP, code, JourneyType.SIGN_IN);

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
        VerifyMfaCodeRequest codeRequest =
                new VerifyMfaCodeRequest(null, code, JourneyType.REGISTRATION);

        var response =
                makeRequest(
                        Optional.of(codeRequest),
                        constructFrontendHeaders(sessionId, CLIENT_SESSION_ID),
                        Map.of());

        assertThat(response, hasStatus(400));
        assertThat(response, hasJsonBody(ErrorResponse.ERROR_1001));
    }

    @ParameterizedTest
    @EnumSource(
            value = JourneyType.class,
            names = {"REGISTRATION", "ACCOUNT_RECOVERY"})
    void whenAuthAppSecretIsMissingReturn400AndDontSetMfaMethod(JourneyType journeyType) {
        setUpAuthAppRequest(journeyType);
        var code = AUTH_APP_STUB.getAuthAppOneTimeCode(ALTERNATIVE_AUTH_APP_SECRET_BASE_32);
        var codeRequest =
                new VerifyMfaCodeRequest(MFAMethodType.AUTH_APP, code, JourneyType.REGISTRATION);

        var response =
                makeRequest(
                        Optional.of(codeRequest),
                        constructFrontendHeaders(sessionId, CLIENT_SESSION_ID),
                        Map.of());

        var isAccountVerified =
                List.of(JourneyType.ACCOUNT_RECOVERY, JourneyType.SIGN_IN).contains(journeyType);
        assertThat(response, hasStatus(400));
        assertThat(response, hasJsonBody(ErrorResponse.ERROR_1043));
        assertTxmaAuditEventsReceived(txmaAuditQueue, singletonList(INVALID_CODE_SENT));
        assertThat(userStore.isAccountVerified(EMAIL_ADDRESS), equalTo(isAccountVerified));
        assertThat(userStore.isAuthAppVerified(EMAIL_ADDRESS), equalTo(isAccountVerified));
        if (isAccountVerified) {
            assertThat(
                    userStore.getMfaMethod(EMAIL_ADDRESS).get(0).getCredentialValue(),
                    equalTo(AUTH_APP_SECRET_BASE_32));
        }
    }

    @ParameterizedTest
    @MethodSource("verifyMfaCodeRequest")
    void whenAuthAppCodeSubmissionBlockedReturn400(
            JourneyType journeyType, String profileInformation) {
        setUpAuthAppRequest(journeyType);
        var authAppSecret =
                journeyType.equals(JourneyType.SIGN_IN)
                        ? AUTH_APP_SECRET_BASE_32
                        : profileInformation;
        String code = AUTH_APP_STUB.getAuthAppOneTimeCode(authAppSecret);
        VerifyMfaCodeRequest codeRequest =
                new VerifyMfaCodeRequest(
                        MFAMethodType.AUTH_APP, code, journeyType, profileInformation);

        var codeRequestType =
                CodeRequestType.getCodeRequestType(MFAMethodType.AUTH_APP, journeyType);
        var codeBlockedKeyPrefix = CODE_BLOCKED_KEY_PREFIX + codeRequestType;
        redis.blockMfaCodesForEmail(EMAIL_ADDRESS, codeBlockedKeyPrefix);

        var response =
                makeRequest(
                        Optional.of(codeRequest),
                        constructFrontendHeaders(sessionId, CLIENT_SESSION_ID),
                        Map.of());

        assertThat(response, hasStatus(400));
        assertThat(response, hasJsonBody(ErrorResponse.ERROR_1042));
        assertTxmaAuditEventsReceived(txmaAuditQueue, singletonList(CODE_MAX_RETRIES_REACHED));
        var isAccountVerified =
                List.of(JourneyType.ACCOUNT_RECOVERY, JourneyType.SIGN_IN).contains(journeyType);

        assertThat(userStore.isAccountVerified(EMAIL_ADDRESS), equalTo(isAccountVerified));
        assertThat(userStore.isAuthAppVerified(EMAIL_ADDRESS), equalTo(isAccountVerified));
        if (isAccountVerified) {
            assertThat(
                    userStore.getMfaMethod(EMAIL_ADDRESS).get(0).getCredentialValue(),
                    equalTo(AUTH_APP_SECRET_BASE_32));
        }
    }

    @Test
    void whenAuthAppCodeRetriesLimitExceededForSignInBlockEmailAndReturn400() {
        setUpAuthAppRequest(JourneyType.SIGN_IN);
        String invalidCode = AUTH_APP_STUB.getAuthAppOneTimeCode("O5ZG63THFVZWKY3SMV2A====");
        VerifyMfaCodeRequest codeRequest =
                new VerifyMfaCodeRequest(MFAMethodType.AUTH_APP, invalidCode, JourneyType.SIGN_IN);

        for (int i = 0; i < 5; i++) {
            redis.increaseMfaCodeAttemptsCount(EMAIL_ADDRESS, MFAMethodType.AUTH_APP);
        }

        assertEquals(5, redis.getMfaCodeAttemptsCount(EMAIL_ADDRESS, MFAMethodType.AUTH_APP));

        var response =
                makeRequest(
                        Optional.of(codeRequest),
                        constructFrontendHeaders(sessionId, CLIENT_SESSION_ID),
                        Map.of());

        var codeRequestType =
                CodeRequestType.getCodeRequestType(
                        codeRequest.getMfaMethodType(), codeRequest.getJourneyType());
        var codeBlockedKeyPrefix = CODE_BLOCKED_KEY_PREFIX + codeRequestType;

        assertThat(response, hasStatus(400));
        assertThat(response, hasJsonBody(ErrorResponse.ERROR_1042));
        assertEquals(0, redis.getMfaCodeAttemptsCount(EMAIL_ADDRESS, MFAMethodType.AUTH_APP));
        assertTrue(redis.isBlockedMfaCodesForEmail(EMAIL_ADDRESS, codeBlockedKeyPrefix));
        assertTrue(userStore.isAccountVerified(EMAIL_ADDRESS));
        assertTrue(userStore.isAuthAppVerified(EMAIL_ADDRESS));
    }

    @ParameterizedTest
    @EnumSource(
            value = JourneyType.class,
            names = {"REGISTRATION", "ACCOUNT_RECOVERY"})
    void whenAuthAppCodeRetriesExceedFiveDontBlockAndReturn400(JourneyType journeyType) {
        for (int i = 0; i < 5; i++) {
            redis.increaseMfaCodeAttemptsCount(EMAIL_ADDRESS, MFAMethodType.AUTH_APP);
        }

        String invalidCode = "999999";
        VerifyMfaCodeRequest codeRequest =
                new VerifyMfaCodeRequest(MFAMethodType.AUTH_APP, invalidCode, journeyType);

        var response =
                makeRequest(
                        Optional.of(codeRequest),
                        constructFrontendHeaders(sessionId, CLIENT_SESSION_ID),
                        Map.of());
        var codeRequestType =
                CodeRequestType.getCodeRequestType(
                        codeRequest.getMfaMethodType(), codeRequest.getJourneyType());
        var codeBlockedKeyPrefix = CODE_BLOCKED_KEY_PREFIX + codeRequestType;

        assertThat(response, hasStatus(400));
        assertThat(response, hasJsonBody(ErrorResponse.ERROR_1043));
        assertFalse(redis.isBlockedMfaCodesForEmail(EMAIL_ADDRESS, codeBlockedKeyPrefix));
    }

    @Test
    void
            whenIncorrectAuthCodesInputtedUpToSmsRetriesLimitAllowSmsAttemptAndReturn400WithoutBlockingFurtherRetries() {
        for (int i = 0; i < 5; i++) {
            redis.increaseMfaCodeAttemptsCount(EMAIL_ADDRESS, MFAMethodType.AUTH_APP);
        }

        String invalidCode = "999999";
        VerifyMfaCodeRequest codeRequest =
                new VerifyMfaCodeRequest(MFAMethodType.SMS, invalidCode, JourneyType.REGISTRATION);

        var response =
                makeRequest(
                        Optional.of(codeRequest),
                        constructFrontendHeaders(sessionId, CLIENT_SESSION_ID),
                        Map.of());
        var codeRequestType =
                CodeRequestType.getCodeRequestType(
                        codeRequest.getMfaMethodType(), codeRequest.getJourneyType());
        var codeBlockedKeyPrefix = CODE_BLOCKED_KEY_PREFIX + codeRequestType;

        assertThat(response, hasStatus(400));
        assertThat(response, hasJsonBody(ErrorResponse.ERROR_1037));
        assertEquals(1, redis.getMfaCodeAttemptsCount(EMAIL_ADDRESS));
        assertFalse(redis.isBlockedMfaCodesForEmail(EMAIL_ADDRESS, codeBlockedKeyPrefix));
    }

    @Test
    void whenValidPhoneNumberOtpCodeForRegistrationReturn204AndSetPhoneNumber() {
        var code = redis.generateAndSavePhoneNumberCode(EMAIL_ADDRESS, 900);
        var codeRequest =
                new VerifyMfaCodeRequest(
                        MFAMethodType.SMS, code, JourneyType.REGISTRATION, PHONE_NUMBER);

        var response =
                makeRequest(
                        Optional.of(codeRequest),
                        constructFrontendHeaders(sessionId, CLIENT_SESSION_ID),
                        Map.of());

        assertThat(response, hasStatus(204));
        assertTxmaAuditEventsReceived(
                txmaAuditQueue, List.of(CODE_VERIFIED, UPDATE_PROFILE_PHONE_NUMBER));
        assertThat(userStore.isAccountVerified(EMAIL_ADDRESS), equalTo(true));
        assertThat(
                redis.getMfaCode(EMAIL_ADDRESS, NotificationType.VERIFY_PHONE_NUMBER),
                equalTo(Optional.empty()));
        assertTrue(
                userStore
                        .getPhoneNumberForUser(EMAIL_ADDRESS)
                        .filter(t -> t.equals(PHONE_NUMBER))
                        .isPresent());
        assertTrue(userStore.isPhoneNumberVerified(EMAIL_ADDRESS));
    }

    @Test
    void whenValidPhoneNumberOtpCodeForAccountRecoveryReturn204AndUpdatePhoneNumber() {
        var code = redis.generateAndSavePhoneNumberCode(EMAIL_ADDRESS, 900);
        userStore.addVerifiedPhoneNumber(EMAIL_ADDRESS, ALTERNATIVE_PHONE_NUMBER);
        userStore.setAccountVerified(EMAIL_ADDRESS);
        var codeRequest =
                new VerifyMfaCodeRequest(
                        MFAMethodType.SMS, code, JourneyType.ACCOUNT_RECOVERY, PHONE_NUMBER);

        var response =
                makeRequest(
                        Optional.of(codeRequest),
                        constructFrontendHeaders(sessionId, CLIENT_SESSION_ID),
                        Map.of());

        assertThat(response, hasStatus(204));
        assertTxmaAuditEventsReceived(
                txmaAuditQueue, List.of(CODE_VERIFIED, UPDATE_PROFILE_PHONE_NUMBER));
        assertThat(userStore.isAccountVerified(EMAIL_ADDRESS), equalTo(true));
        assertTrue(
                userStore
                        .getPhoneNumberForUser(EMAIL_ADDRESS)
                        .filter(t -> t.equals(PHONE_NUMBER))
                        .isPresent());
        assertTrue(userStore.isPhoneNumberVerified(EMAIL_ADDRESS));
        assertThat(Objects.isNull(userStore.getMfaMethod(EMAIL_ADDRESS)), equalTo(true));
    }

    @Test
    void
            whenValidPhoneNumberOtpCodeForAccountRecoveryReturn204UpdatePhoneNumberAndRemoveAuthAppWhenPresent() {
        var code = redis.generateAndSavePhoneNumberCode(EMAIL_ADDRESS, 900);
        setUpAuthAppRequest(JourneyType.ACCOUNT_RECOVERY);
        var codeRequest =
                new VerifyMfaCodeRequest(
                        MFAMethodType.SMS, code, JourneyType.ACCOUNT_RECOVERY, PHONE_NUMBER);

        var response =
                makeRequest(
                        Optional.of(codeRequest),
                        constructFrontendHeaders(sessionId, CLIENT_SESSION_ID),
                        Map.of());

        assertThat(response, hasStatus(204));
        assertTxmaAuditEventsReceived(
                txmaAuditQueue, List.of(CODE_VERIFIED, UPDATE_PROFILE_PHONE_NUMBER));
        assertThat(userStore.isAccountVerified(EMAIL_ADDRESS), equalTo(true));
        assertTrue(
                userStore
                        .getPhoneNumberForUser(EMAIL_ADDRESS)
                        .filter(t -> t.equals(PHONE_NUMBER))
                        .isPresent());
        assertTrue(userStore.isPhoneNumberVerified(EMAIL_ADDRESS));
        assertThat(userStore.getMfaMethod(EMAIL_ADDRESS).isEmpty(), equalTo(true));
    }

    @Test
    void shouldReturn204WhenSuccessfulSMSRegistrationRequestAndOverwriteExistingPhoneNumber() {
        userStore.addVerifiedPhoneNumber(EMAIL_ADDRESS, "+447700900111");
        var code = redis.generateAndSavePhoneNumberCode(EMAIL_ADDRESS, 900);
        var codeRequest =
                new VerifyMfaCodeRequest(
                        MFAMethodType.SMS, code, JourneyType.REGISTRATION, PHONE_NUMBER);

        var response =
                makeRequest(
                        Optional.of(codeRequest),
                        constructFrontendHeaders(sessionId, CLIENT_SESSION_ID),
                        Map.of());

        assertThat(response, hasStatus(204));
        assertTxmaAuditEventsReceived(
                txmaAuditQueue, List.of(CODE_VERIFIED, UPDATE_PROFILE_PHONE_NUMBER));
        assertThat(userStore.isAccountVerified(EMAIL_ADDRESS), equalTo(true));
        assertThat(userStore.getPhoneNumberForUser(EMAIL_ADDRESS).get(), equalTo(PHONE_NUMBER));
        assertTrue(userStore.isPhoneNumberVerified(EMAIL_ADDRESS));
    }

    @Test
    void whenValidPhoneNumberCodeForRegistrationReturn204AndInvalidateAuthApp() {
        userStore.addMfaMethod(
                EMAIL_ADDRESS, MFAMethodType.AUTH_APP, false, true, AUTH_APP_SECRET_BASE_32);
        var code = redis.generateAndSavePhoneNumberCode(EMAIL_ADDRESS, 900);
        var codeRequest =
                new VerifyMfaCodeRequest(
                        MFAMethodType.SMS, code, JourneyType.REGISTRATION, PHONE_NUMBER);

        var response =
                makeRequest(
                        Optional.of(codeRequest),
                        constructFrontendHeaders(sessionId, CLIENT_SESSION_ID),
                        Map.of());

        assertThat(response, hasStatus(204));
        assertTxmaAuditEventsReceived(
                txmaAuditQueue, List.of(CODE_VERIFIED, UPDATE_PROFILE_PHONE_NUMBER));
        assertThat(userStore.isAuthAppEnabled(EMAIL_ADDRESS), equalTo(false));
        assertThat(userStore.isAccountVerified(EMAIL_ADDRESS), equalTo(true));
        assertThat(userStore.getPhoneNumberForUser(EMAIL_ADDRESS).get(), equalTo(PHONE_NUMBER));
        assertTrue(userStore.isPhoneNumberVerified(EMAIL_ADDRESS));
    }

    @ParameterizedTest
    @EnumSource(
            value = JourneyType.class,
            names = {"REGISTRATION", "ACCOUNT_RECOVERY"})
    void whenInvalidPhoneNumberCodeHasExpiredReturn400(JourneyType journeyType) {
        setUpSmsRequest(journeyType, PHONE_NUMBER);
        var code = redis.generateAndSavePhoneNumberCode(EMAIL_ADDRESS, 1);
        var codeRequest =
                new VerifyMfaCodeRequest(
                        MFAMethodType.SMS, code, journeyType, ALTERNATIVE_PHONE_NUMBER);

        await().pollDelay(Duration.ofSeconds(2)).untilAsserted(() -> assertTrue(true));

        var response =
                makeRequest(
                        Optional.of(codeRequest),
                        constructFrontendHeaders(sessionId, CLIENT_SESSION_ID),
                        Map.of());

        assertThat(response, hasStatus(400));
        assertThat(response, hasJsonBody(ErrorResponse.ERROR_1037));
        assertTxmaAuditEventsReceived(txmaAuditQueue, List.of(INVALID_CODE_SENT));

        var isAccountVerified = journeyType.equals(JourneyType.ACCOUNT_RECOVERY);
        var expectedPhoneNumber =
                journeyType.equals(JourneyType.ACCOUNT_RECOVERY) ? PHONE_NUMBER : null;
        ;
        assertThat(
                userStore.getPhoneNumberForUser(EMAIL_ADDRESS).orElse(null),
                equalTo(expectedPhoneNumber));
        assertThat(userStore.isPhoneNumberVerified(EMAIL_ADDRESS), equalTo(isAccountVerified));
        assertThat(userStore.isAccountVerified(EMAIL_ADDRESS), equalTo(isAccountVerified));
    }

    @ParameterizedTest
    @EnumSource(
            value = JourneyType.class,
            names = {"REGISTRATION", "ACCOUNT_RECOVERY"})
    void whenInvalidPhoneNumberCodeReturn400(JourneyType journeyType) {
        setUpSmsRequest(journeyType, PHONE_NUMBER);
        var codeRequest =
                new VerifyMfaCodeRequest(
                        MFAMethodType.SMS, "123456", journeyType, ALTERNATIVE_PHONE_NUMBER);

        var response =
                makeRequest(
                        Optional.of(codeRequest),
                        constructFrontendHeaders(sessionId, CLIENT_SESSION_ID),
                        Map.of());

        assertThat(response, hasStatus(400));
        assertThat(response, hasJsonBody(ErrorResponse.ERROR_1037));
        assertTxmaAuditEventsReceived(txmaAuditQueue, List.of(INVALID_CODE_SENT));
        var isAccountVerified = journeyType.equals(JourneyType.ACCOUNT_RECOVERY);
        var expectedPhoneNumber =
                journeyType.equals(JourneyType.ACCOUNT_RECOVERY) ? PHONE_NUMBER : null;
        assertThat(
                userStore.getPhoneNumberForUser(EMAIL_ADDRESS).orElse(null),
                equalTo(expectedPhoneNumber));
        assertThat(userStore.isPhoneNumberVerified(EMAIL_ADDRESS), equalTo(isAccountVerified));
        assertThat(userStore.isAccountVerified(EMAIL_ADDRESS), equalTo(isAccountVerified));
    }

    @ParameterizedTest
    @EnumSource(
            value = JourneyType.class,
            names = {"REGISTRATION", "ACCOUNT_RECOVERY"})
    void whenPhoneNumberCodeIsBlockedReturn400(JourneyType journeyType) throws Json.JsonException {
        setUpSmsRequest(journeyType, PHONE_NUMBER);

        redis.addEmailToSession(sessionId, EMAIL_ADDRESS);
        var codeRequestType = CodeRequestType.getCodeRequestType(MFAMethodType.SMS, journeyType);
        var codeBlockedKeyPrefix = CODE_BLOCKED_KEY_PREFIX + codeRequestType;
        redis.blockMfaCodesForEmail(EMAIL_ADDRESS, codeBlockedKeyPrefix);

        var codeRequest =
                new VerifyMfaCodeRequest(
                        MFAMethodType.SMS, "123456", journeyType, ALTERNATIVE_PHONE_NUMBER);

        var response =
                makeRequest(
                        Optional.of(codeRequest), constructFrontendHeaders(sessionId), Map.of());

        assertThat(response, hasStatus(400));
        assertThat(response, hasJsonBody(ErrorResponse.ERROR_1034));
        assertTxmaAuditEventsReceived(txmaAuditQueue, singletonList(CODE_MAX_RETRIES_REACHED));

        var isAccountVerified = journeyType.equals(JourneyType.ACCOUNT_RECOVERY);
        var expectedPhoneNumber =
                journeyType.equals(JourneyType.ACCOUNT_RECOVERY) ? PHONE_NUMBER : null;
        assertThat(
                userStore.getPhoneNumberForUser(EMAIL_ADDRESS).orElse(null),
                equalTo(expectedPhoneNumber));
        assertThat(userStore.isPhoneNumberVerified(EMAIL_ADDRESS), equalTo(isAccountVerified));
        assertThat(userStore.isAccountVerified(EMAIL_ADDRESS), equalTo(isAccountVerified));
    }

    @ParameterizedTest
    @EnumSource(
            value = JourneyType.class,
            names = {"REGISTRATION", "ACCOUNT_RECOVERY"})
    void whenPhoneNumberCodeRetriesLimitExceededBlockEmailAndReturn400(JourneyType journeyType)
            throws Json.JsonException {
        setUpSmsRequest(journeyType, PHONE_NUMBER);
        redis.addEmailToSession(sessionId, EMAIL_ADDRESS);

        var codeRequest =
                new VerifyMfaCodeRequest(
                        MFAMethodType.SMS, "123456", journeyType, ALTERNATIVE_PHONE_NUMBER);

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
        var isAccountVerified = journeyType.equals(JourneyType.ACCOUNT_RECOVERY);
        var expectedPhoneNumber =
                journeyType.equals(JourneyType.ACCOUNT_RECOVERY) ? PHONE_NUMBER : null;
        assertThat(
                userStore.getPhoneNumberForUser(EMAIL_ADDRESS).orElse(null),
                equalTo(expectedPhoneNumber));
        assertThat(userStore.isPhoneNumberVerified(EMAIL_ADDRESS), equalTo(isAccountVerified));
        assertThat(userStore.isAccountVerified(EMAIL_ADDRESS), equalTo(isAccountVerified));
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

    public void setUpAuthAppRequest(JourneyType journeyType) {
        if (!journeyType.equals(JourneyType.REGISTRATION)) {
            userStore.setAccountVerified(EMAIL_ADDRESS);
            userStore.addMfaMethod(
                    EMAIL_ADDRESS, MFAMethodType.AUTH_APP, true, true, AUTH_APP_SECRET_BASE_32);
        }
    }

    public void setUpSmsRequest(JourneyType journeyType, String phoneNumber) {
        if (!journeyType.equals(JourneyType.REGISTRATION)) {
            userStore.setAccountVerified(EMAIL_ADDRESS);
            userStore.addVerifiedPhoneNumber(EMAIL_ADDRESS, phoneNumber);
        }
    }
}
