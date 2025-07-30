package uk.gov.di.authentication.api;

import com.nimbusds.oauth2.sdk.id.ClientID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent;
import uk.gov.di.authentication.frontendapi.entity.CheckUserExistsRequest;
import uk.gov.di.authentication.frontendapi.entity.CheckUserExistsResponse;
import uk.gov.di.authentication.frontendapi.lambda.CheckUserExistsHandler;
import uk.gov.di.authentication.shared.entity.CodeRequestType;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.helpers.IdGenerator;
import uk.gov.di.authentication.shared.serialization.Json.JsonException;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;

import java.net.URI;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_ACCOUNT_TEMPORARILY_LOCKED;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_CHECK_USER_KNOWN_EMAIL;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_CHECK_USER_NO_ACCOUNT_WITH_EMAIL;
import static uk.gov.di.authentication.shared.helpers.TxmaAuditHelper.TXMA_AUDIT_ENCODED_HEADER;
import static uk.gov.di.authentication.shared.services.CodeStorageService.CODE_BLOCKED_KEY_PREFIX;
import static uk.gov.di.authentication.sharedtest.helper.AuditAssertionsHelper.assertTxmaAuditEventsReceived;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class CheckUserExistsIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    private static final URI REDIRECT_URI =
            URI.create(System.getenv("STUB_RELYING_PARTY_REDIRECT_URI"));
    private static final ClientID CLIENT_ID = new ClientID("test-client");
    private static final String CLIENT_NAME = "some-client-name";
    private static final String SECTOR_IDENTIFIER_HOST = "test.com";
    private static final String TEST_EMAIL_1 = "joe.bloggs+1@digital.cabinet-office.gov.uk";
    private static final String TEST_EMAIL_2 = "joe.bloggs+2@digital.cabinet-office.gov.uk";
    private static final String TEST_PASSWORD = "password-1";
    private static final String TEST_PHONE_NUMBER = "+44987654321";
    private static final String TEST_CREDENTIAL = "credential";

    @BeforeEach
    void setUp() {
        handler = new CheckUserExistsHandler(TXMA_ENABLED_CONFIGURATION_SERVICE);
        txmaAuditQueue.clear();
    }

    @Nested
    @DisplayName("Successful user lookup")
    class SuccessfulUserLookup {

        @ParameterizedTest
        @EnumSource(
                value = MFAMethodType.class,
                names = {"SMS", "AUTH_APP"})
        @DisplayName("User can check if their account exists with MFA configured")
        void userCanCheckIfTheirAccountExistsWithMfaConfigured(MFAMethodType mfaMethodType)
                throws JsonException {
            var sessionId = setupUserAndSession(TEST_EMAIL_1, mfaMethodType);
            var clientSessionId = IdGenerator.generate();

            var request = new CheckUserExistsRequest(TEST_EMAIL_1);
            var response =
                    makeRequest(
                            Optional.of(request),
                            constructFrontendHeaders(sessionId, clientSessionId),
                            Map.of());

            assertThat(response, hasStatus(200));
            CheckUserExistsResponse checkUserExistsResponse =
                    objectMapper.readValue(response.getBody(), CheckUserExistsResponse.class);
            assertThat(checkUserExistsResponse.email(), equalTo(TEST_EMAIL_1));
            assertThat(checkUserExistsResponse.mfaMethodType(), equalTo(mfaMethodType));
            assertTrue(checkUserExistsResponse.doesUserExist());

            if (MFAMethodType.SMS.equals(mfaMethodType)) {
                assertThat(checkUserExistsResponse.phoneNumberLastThree(), equalTo("321"));
            } else {
                assertNull(checkUserExistsResponse.phoneNumberLastThree());
            }

            assertExpectedAuditEvents(AUTH_CHECK_USER_KNOWN_EMAIL);
        }

        @Test
        @DisplayName("User can check account status when MFA is temporarily locked")
        void userCanCheckAccountStatusWhenMfaIsTemporarilyLocked() throws JsonException {
            var sessionId = setupUserAndSession(TEST_EMAIL_1, MFAMethodType.AUTH_APP);
            var clientSessionId = IdGenerator.generate();

            var codeRequestType =
                    CodeRequestType.getCodeRequestType(MFAMethodType.AUTH_APP, JourneyType.SIGN_IN);
            var codeBlockedKeyPrefix = CODE_BLOCKED_KEY_PREFIX + codeRequestType;
            redis.blockMfaCodesForEmail(TEST_EMAIL_1, codeBlockedKeyPrefix);

            var request = new CheckUserExistsRequest(TEST_EMAIL_1);
            var response =
                    makeRequest(
                            Optional.of(request),
                            constructFrontendHeaders(sessionId, clientSessionId),
                            Map.of());

            assertThat(response, hasStatus(200));
            CheckUserExistsResponse checkUserExistsResponse =
                    objectMapper.readValue(response.getBody(), CheckUserExistsResponse.class);
            assertThat(checkUserExistsResponse.email(), equalTo(TEST_EMAIL_1));
            assertThat(checkUserExistsResponse.mfaMethodType(), equalTo(MFAMethodType.AUTH_APP));
            assertTrue(checkUserExistsResponse.doesUserExist());

            var lockoutInformation = checkUserExistsResponse.lockoutInformation();
            assertNotNull(lockoutInformation);
            assertThat(lockoutInformation.get(0).lockTTL() > 0, is(true));
            assertThat(lockoutInformation.get(0).journeyType(), is(JourneyType.SIGN_IN));
            assertThat(lockoutInformation.get(0).mfaMethodType(), is(MFAMethodType.AUTH_APP));

            assertExpectedAuditEvents(AUTH_CHECK_USER_KNOWN_EMAIL);
        }

        @Test
        @DisplayName("User can check if account does not exist")
        void userCanCheckIfAccountDoesNotExist() throws JsonException {
            var sessionId = IdGenerator.generate();
            authSessionStore.addSession(sessionId);
            var clientSessionId = IdGenerator.generate();
            setupClient(TEST_EMAIL_2, sessionId);

            var request = new CheckUserExistsRequest(TEST_EMAIL_2);
            var response =
                    makeRequest(
                            Optional.of(request),
                            constructFrontendHeaders(sessionId, clientSessionId),
                            Map.of());

            assertThat(response, hasStatus(200));
            CheckUserExistsResponse checkUserExistsResponse =
                    objectMapper.readValue(response.getBody(), CheckUserExistsResponse.class);
            assertThat(checkUserExistsResponse.email(), equalTo(TEST_EMAIL_2));
            assertThat(checkUserExistsResponse.mfaMethodType(), equalTo(MFAMethodType.NONE));
            assertFalse(checkUserExistsResponse.doesUserExist());
            assertNull(checkUserExistsResponse.phoneNumberLastThree());

            assertExpectedAuditEvents(AUTH_CHECK_USER_NO_ACCOUNT_WITH_EMAIL);
        }
    }

    @Test
    @DisplayName("User cannot check account when temporarily locked")
    void userCannotCheckAccountWhenTemporarilyLocked() {
        var sessionId = IdGenerator.generate();
        authSessionStore.addSession(sessionId);
        redis.blockMfaCodesForEmail(
                TEST_EMAIL_2,
                CodeStorageService.PASSWORD_BLOCKED_KEY_PREFIX + JourneyType.PASSWORD_RESET);

        var headers = new HashMap<String, String>();
        headers.put("Session-Id", sessionId);
        headers.put("X-API-Key", FRONTEND_API_KEY);
        headers.put(TXMA_AUDIT_ENCODED_HEADER, ENCODED_DEVICE_INFORMATION);

        var request = new CheckUserExistsRequest(TEST_EMAIL_2);
        var response = makeRequest(Optional.of(request), headers, Map.of());

        assertThat(response, hasStatus(400));
        assertThat(response, hasJsonBody(ErrorResponse.ACCT_TEMPORARILY_LOCKED));

        assertExpectedAuditEvents(AUTH_ACCOUNT_TEMPORARILY_LOCKED);
    }

    @Test
    @DisplayName("Existing user cannot check account when password locked")
    void existingUserCannotCheckAccountWhenPasswordLocked() {
        var sessionId = setupUserAndSession(TEST_EMAIL_1, MFAMethodType.SMS);
        var clientSessionId = IdGenerator.generate();
        redis.blockMfaCodesForEmail(
                TEST_EMAIL_1,
                CodeStorageService.PASSWORD_BLOCKED_KEY_PREFIX + JourneyType.PASSWORD_RESET);

        var request = new CheckUserExistsRequest(TEST_EMAIL_1);
        var response =
                makeRequest(
                        Optional.of(request),
                        constructFrontendHeaders(sessionId, clientSessionId),
                        Map.of());

        assertThat(response, hasStatus(400));
        assertThat(response, hasJsonBody(ErrorResponse.ACCT_TEMPORARILY_LOCKED));

        assertExpectedAuditEvents(AUTH_ACCOUNT_TEMPORARILY_LOCKED);
    }

    @Test
    @DisplayName("User with both password and auth app lockouts returns password lockout")
    void userWithMultipleLockoutTypesReturnsPasswordLockout() {
        var sessionId = setupUserAndSession(TEST_EMAIL_1, MFAMethodType.AUTH_APP);
        var clientSessionId = IdGenerator.generate();

        // Block both password and auth app
        redis.blockMfaCodesForEmail(
                TEST_EMAIL_1,
                CodeStorageService.PASSWORD_BLOCKED_KEY_PREFIX + JourneyType.PASSWORD_RESET);
        var codeRequestType =
                CodeRequestType.getCodeRequestType(MFAMethodType.AUTH_APP, JourneyType.SIGN_IN);
        redis.blockMfaCodesForEmail(TEST_EMAIL_1, CODE_BLOCKED_KEY_PREFIX + codeRequestType);

        var request = new CheckUserExistsRequest(TEST_EMAIL_1);
        var response =
                makeRequest(
                        Optional.of(request),
                        constructFrontendHeaders(sessionId, clientSessionId),
                        Map.of());

        assertThat(response, hasStatus(400));
        assertThat(response, hasJsonBody(ErrorResponse.ACCT_TEMPORARILY_LOCKED));

        assertExpectedAuditEvents(AUTH_ACCOUNT_TEMPORARILY_LOCKED);
    }

    @Test
    @DisplayName("User with no active lockouts returns empty lockout information")
    void userWithNoActiveLockoutsReturnsEmptyLockoutInformation() throws JsonException {
        var sessionId = setupUserAndSession(TEST_EMAIL_1, MFAMethodType.AUTH_APP);
        var clientSessionId = IdGenerator.generate();

        var request = new CheckUserExistsRequest(TEST_EMAIL_1);
        var response =
                makeRequest(
                        Optional.of(request),
                        constructFrontendHeaders(sessionId, clientSessionId),
                        Map.of());

        assertThat(response, hasStatus(200));
        CheckUserExistsResponse checkUserExistsResponse =
                objectMapper.readValue(response.getBody(), CheckUserExistsResponse.class);
        assertThat(checkUserExistsResponse.lockoutInformation().size(), equalTo(0));

        assertExpectedAuditEvents(AUTH_CHECK_USER_KNOWN_EMAIL);
    }

    private String setupUserAndSession(String emailAddress, MFAMethodType mfaMethodType) {
        var sessionId = IdGenerator.generate();
        authSessionStore.addSession(sessionId);
        authSessionStore.addClientIdToSession(sessionId, CLIENT_ID.getValue());

        userStore.signUp(emailAddress, TEST_PASSWORD);
        userStore.addSalt(emailAddress);

        if (MFAMethodType.SMS == mfaMethodType) {
            userStore.addMfaMethod(emailAddress, mfaMethodType, false, true, TEST_CREDENTIAL);
            userStore.addVerifiedPhoneNumber(emailAddress, TEST_PHONE_NUMBER);
        } else {
            userStore.addMfaMethod(emailAddress, mfaMethodType, true, true, TEST_CREDENTIAL);
        }

        setupClient(emailAddress, sessionId);

        return sessionId;
    }

    private void setupClient(String emailAddress, String sessionId) {
        registerClient(
                emailAddress,
                CLIENT_ID,
                CLIENT_NAME,
                REDIRECT_URI,
                "https://" + SECTOR_IDENTIFIER_HOST);
        authSessionStore.addRpSectorIdentifierHostToSession(sessionId, SECTOR_IDENTIFIER_HOST);
    }

    private void assertExpectedAuditEvents(FrontendAuditableEvent... events) {
        assertTxmaAuditEventsReceived(txmaAuditQueue, List.of(events));
    }
}
