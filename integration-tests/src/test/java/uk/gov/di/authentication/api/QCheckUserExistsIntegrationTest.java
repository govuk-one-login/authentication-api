package uk.gov.di.authentication.api;

import com.nimbusds.oauth2.sdk.id.ClientID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import uk.gov.di.authentication.frontendapi.entity.CheckUserExistsRequest;
import uk.gov.di.authentication.frontendapi.entity.CheckUserExistsResponse;
import uk.gov.di.authentication.frontendapi.lambda.CheckUserExistsHandler;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.helpers.IdGenerator;
import uk.gov.di.authentication.shared.serialization.Json.JsonException;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;

import java.net.URI;
import java.net.URISyntaxException;
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
import static uk.gov.di.authentication.shared.services.CodeStorageService.CODE_BLOCKED_KEY_PREFIX;
import static uk.gov.di.authentication.sharedtest.helper.AuditAssertionsHelper.assertTxmaAuditEventsReceived;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class QCheckUserExistsIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    private static final String TEST_EMAIL = "joe.bloggs+1@digital.cabinet-office.gov.uk";
    private static final String TEST_EMAIL_2 = "joe.bloggs+2@digital.cabinet-office.gov.uk";
    private static final String TEST_PASSWORD = "password-1";
    private static final String TEST_PHONE_NUMBER = "+44987654321";
    private static final String MFA_CREDENTIAL = "credential";
    private static final URI REDIRECT_URI = URI.create(System.getenv("STUB_RELYING_PARTY_REDIRECT_URI"));
    private static final ClientID CLIENT_ID = new ClientID("test-client");
    private static final String CLIENT_NAME = "some-client-name";
    private static final String SECTOR_IDENTIFIER_HOST = "test.com";

    @BeforeEach
    void setUp() {
        handler = new CheckUserExistsHandler(TXMA_ENABLED_CONFIGURATION_SERVICE, redisConnectionService);
        txmaAuditQueue.clear();
    }

    @Nested
    @DisplayName("Successful user existence checks")
    class SuccessfulUserExistenceChecks {

        @ParameterizedTest
        @EnumSource(value = MFAMethodType.class, names = {"SMS", "AUTH_APP"})
        @DisplayName("User can check if account exists with MFA method configured")
        void userCanCheckIfAccountExistsWithMfaMethodConfigured(MFAMethodType mfaMethodType) throws JsonException, URISyntaxException {
            var sessionId = setupSessionAndClient();
            var clientSessionId = IdGenerator.generate();
            userStore.signUp(TEST_EMAIL, TEST_PASSWORD);
            var salt = userStore.addSalt(TEST_EMAIL);

            var userProfile = userStore.getUserProfileFromEmail(TEST_EMAIL).orElseThrow();
            var expectedInternalCommonSubjectId = ClientSubjectHelper.calculatePairwiseIdentifier(
                    userProfile.getSubjectID(),
                    new URI(TXMA_ENABLED_CONFIGURATION_SERVICE.getInternalSectorUri()),
                    salt);

            if (MFAMethodType.SMS == mfaMethodType) {
                userStore.addMfaMethod(TEST_EMAIL, mfaMethodType, false, true, MFA_CREDENTIAL);
                userStore.addVerifiedPhoneNumber(TEST_EMAIL, TEST_PHONE_NUMBER);
            } else {
                userStore.addMfaMethod(TEST_EMAIL, mfaMethodType, true, true, MFA_CREDENTIAL);
            }

            var request = new CheckUserExistsRequest(TEST_EMAIL);
            var response = makeRequest(
                    Optional.of(request),
                    constructFrontendHeaders(sessionId, clientSessionId),
                    Map.of());

            assertThat(response, hasStatus(200));
            CheckUserExistsResponse checkUserExistsResponse = objectMapper.readValue(response.getBody(), CheckUserExistsResponse.class);
            assertThat(checkUserExistsResponse.email(), equalTo(TEST_EMAIL));
            assertThat(checkUserExistsResponse.mfaMethodType(), equalTo(mfaMethodType));
            assertTrue(checkUserExistsResponse.doesUserExist());
            assertThat(
                    authSessionStore.getSession(sessionId).orElseThrow().getInternalCommonSubjectId(),
                    equalTo(expectedInternalCommonSubjectId));
            if (MFAMethodType.SMS.equals(mfaMethodType)) {
                assertThat(checkUserExistsResponse.phoneNumberLastThree(), equalTo("321"));
            } else if (MFAMethodType.AUTH_APP.equals(mfaMethodType)) {
                assertNull(checkUserExistsResponse.phoneNumberLastThree());
            }
            assertTxmaAuditEventsReceived(txmaAuditQueue, List.of(AUTH_CHECK_USER_KNOWN_EMAIL));
        }

        @Test
        @DisplayName("User can check account existence and receive lockout information for Auth App MFA")
        void userCanCheckAccountExistenceAndReceiveLockoutInformationForAuthAppMfa() throws JsonException {
            var sessionId = setupSessionAndClient();
            var clientSessionId = IdGenerator.generate();
            userStore.signUp(TEST_EMAIL, TEST_PASSWORD);
            userStore.addMfaMethod(TEST_EMAIL, MFAMethodType.AUTH_APP, true, true, MFA_CREDENTIAL);

            var codeBlockedKeyPrefix = CODE_BLOCKED_KEY_PREFIX + "AUTH_APP_SIGN_IN";
            redis.blockMfaCodesForEmail(TEST_EMAIL, codeBlockedKeyPrefix);

            var request = new CheckUserExistsRequest(TEST_EMAIL);
            var response = makeRequest(
                    Optional.of(request),
                    constructFrontendHeaders(sessionId, clientSessionId),
                    Map.of());

            assertThat(response, hasStatus(200));
            CheckUserExistsResponse checkUserExistsResponse = objectMapper.readValue(response.getBody(), CheckUserExistsResponse.class);
            assertThat(checkUserExistsResponse.email(), equalTo(TEST_EMAIL));
            assertThat(checkUserExistsResponse.mfaMethodType(), equalTo(MFAMethodType.AUTH_APP));
            assertTrue(checkUserExistsResponse.doesUserExist());
            var lockoutInformation = checkUserExistsResponse.lockoutInformation();
            assertNotNull(lockoutInformation);
            assertThat(lockoutInformation.get(0).lockTTL() > 0, is(true));
            assertThat(lockoutInformation.get(0).journeyType(), is(JourneyType.SIGN_IN));
            assertThat(lockoutInformation.get(0).mfaMethodType(), is(MFAMethodType.AUTH_APP));

            assertTxmaAuditEventsReceived(txmaAuditQueue, List.of(AUTH_CHECK_USER_KNOWN_EMAIL));
        }

        @Test
        @DisplayName("User can check if account does not exist")
        void userCanCheckIfAccountDoesNotExist() throws JsonException {
            var sessionId = setupSessionAndClient(TEST_EMAIL_2);
            var clientSessionId = IdGenerator.generate();
            var request = new CheckUserExistsRequest(TEST_EMAIL_2);

            var response = makeRequest(
                    Optional.of(request),
                    constructFrontendHeaders(sessionId, clientSessionId),
                    Map.of());

            assertThat(response, hasStatus(200));
            CheckUserExistsResponse checkUserExistsResponse = objectMapper.readValue(response.getBody(), CheckUserExistsResponse.class);
            assertThat(checkUserExistsResponse.email(), equalTo(TEST_EMAIL_2));
            assertThat(checkUserExistsResponse.mfaMethodType(), equalTo(MFAMethodType.NONE));
            assertFalse(checkUserExistsResponse.doesUserExist());
            assertNull(checkUserExistsResponse.phoneNumberLastThree());
            assertTxmaAuditEventsReceived(txmaAuditQueue, List.of(AUTH_CHECK_USER_NO_ACCOUNT_WITH_EMAIL));
        }
    }

    @Nested
    @DisplayName("Error cases")
    class ErrorCases {

        @Test
        @DisplayName("Account temporarily locked error prevents user from checking account existence")
        void accountTemporarilyLockedErrorPreventsUserFromCheckingAccountExistence() throws JsonException {
            var sessionId = IdGenerator.generate();
            authSessionStore.addSession(sessionId);
            redis.blockMfaCodesForEmail(
                    TEST_EMAIL_2,
                    CodeStorageService.PASSWORD_BLOCKED_KEY_PREFIX + JourneyType.PASSWORD_RESET);

            var request = new CheckUserExistsRequest(TEST_EMAIL_2);
            var response = makeRequest(
                    Optional.of(request),
                    constructFrontendHeaders(sessionId),
                    Map.of("Session-Id", sessionId, "X-API-Key", FRONTEND_API_KEY),
                    Map.of());

            assertThat(response, hasStatus(400));
            assertThat(response, hasJsonBody(ErrorResponse.ACCT_TEMPORARILY_LOCKED));
            assertTxmaAuditEventsReceived(txmaAuditQueue, List.of(AUTH_ACCOUNT_TEMPORARILY_LOCKED));
        }
    }

    private String setupSessionAndClient() {
        return setupSessionAndClient(TEST_EMAIL);
    }

    private String setupSessionAndClient(String emailAddress) {
        var sessionId = IdGenerator.generate();
        authSessionStore.addSession(sessionId);
        authSessionStore.addClientIdToSession(sessionId, CLIENT_ID.getValue());
        registerClient(
                emailAddress,
                CLIENT_ID,
                CLIENT_NAME,
                REDIRECT_URI,
                "https://" + SECTOR_IDENTIFIER_HOST);
        authSessionStore.addRpSectorIdentifierHostToSession(sessionId, SECTOR_IDENTIFIER_HOST);
        return sessionId;
    }
}
