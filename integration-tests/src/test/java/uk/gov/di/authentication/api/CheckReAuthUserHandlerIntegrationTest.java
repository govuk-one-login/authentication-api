package uk.gov.di.authentication.api;

import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.authentication.frontendapi.entity.CheckReauthUserRequest;
import uk.gov.di.authentication.frontendapi.lambda.CheckReAuthUserHandler;
import uk.gov.di.authentication.shared.entity.CountType;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.AuthenticationAttemptsService;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;
import uk.gov.di.authentication.sharedtest.extensions.AuthSessionExtension;
import uk.gov.di.authentication.sharedtest.extensions.AuthenticationAttemptsStoreExtension;
import uk.gov.di.authentication.sharedtest.helper.AuditEventExpectation;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.IntStream;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_REAUTH_ACCOUNT_IDENTIFIED;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_REAUTH_FAILED;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_REAUTH_INCORRECT_EMAIL_ENTERED;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_REAUTH_INCORRECT_EMAIL_LIMIT_BREACHED;
import static uk.gov.di.authentication.shared.helpers.TxmaAuditHelper.TXMA_AUDIT_ENCODED_HEADER;
import static uk.gov.di.authentication.sharedtest.helper.AuditAssertionsHelper.assertAuditEventExpectations;
import static uk.gov.di.authentication.testsupport.AuditTestConstants.ATTEMPT_NO_FAILED_AT;
import static uk.gov.di.authentication.testsupport.AuditTestConstants.FAILURE_REASON;
import static uk.gov.di.authentication.testsupport.AuditTestConstants.INCORRECT_EMAIL_ATTEMPT_COUNT;
import static uk.gov.di.authentication.testsupport.AuditTestConstants.INCORRECT_OTP_CODE_ATTEMPT_COUNT;
import static uk.gov.di.authentication.testsupport.AuditTestConstants.INCORRECT_PASSWORD_ATTEMPT_COUNT;
import static uk.gov.di.authentication.testsupport.AuditTestConstants.RP_PAIRWISE_ID;
import static uk.gov.di.authentication.testsupport.AuditTestConstants.USER_ID_FOR_USER_SUPPLIED_EMAIL;
import static uk.gov.di.authentication.testsupport.AuditTestConstants.USER_SUPPLIED_EMAIL;
import static uk.gov.di.orchestration.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.orchestration.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

public class CheckReAuthUserHandlerIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    private static final String TEST_EMAIL = "joe.bloggs@digital.cabinet-office.gov.uk";
    private static final String INTERNAL_SECTOR_HOST = "test.account.gov.uk";
    private static final String CLIENT_SESSION_ID = "a-client-session-id";
    private static final ClientID CLIENT_ID = new ClientID("test-client");
    private static final Subject SUBJECT = new Subject();
    private static final String SESSION_ID = "test-session-id";
    private Map<String, String> requestHeaders;

    private static final AuditEventExpectation BASE_REAUTH_FAILED_EXPECTATION =
            new AuditEventExpectation(AUTH_REAUTH_FAILED)
                    .withAttribute(INCORRECT_EMAIL_ATTEMPT_COUNT, "6")
                    .withAttribute(INCORRECT_PASSWORD_ATTEMPT_COUNT, "0")
                    .withAttribute(FAILURE_REASON, "incorrect_email");

    private static final AuditEventExpectation BASE_INCORRECT_EMAIL_ENTERED_EXPECTATION =
            new AuditEventExpectation(AUTH_REAUTH_INCORRECT_EMAIL_ENTERED)
                    .withAttribute(INCORRECT_EMAIL_ATTEMPT_COUNT, "6")
                    .withAttribute(USER_SUPPLIED_EMAIL, TEST_EMAIL)
                    .withAttribute(USER_ID_FOR_USER_SUPPLIED_EMAIL, SUBJECT.getValue());

    private static final AuditEventExpectation BASE_LIMIT_BREACHED_EXPECTATION =
            new AuditEventExpectation(AUTH_REAUTH_INCORRECT_EMAIL_LIMIT_BREACHED)
                    .withAttribute(ATTEMPT_NO_FAILED_AT, "6");

    @RegisterExtension
    protected static final AuthenticationAttemptsStoreExtension authCodeExtension =
            new AuthenticationAttemptsStoreExtension();

    @RegisterExtension
    protected static final AuthSessionExtension authSessionExtension = new AuthSessionExtension();

    public static final String ENCODED_DEVICE_INFORMATION =
            "R21vLmd3QilNKHJsaGkvTFxhZDZrKF44SStoLFsieG0oSUY3aEhWRVtOMFRNMVw1dyInKzB8OVV5N09hOi8kLmlLcWJjJGQiK1NPUEJPPHBrYWJHP358NDg2ZDVc";

    private static final IntegrationTestConfigurationService CONFIGURATION_SERVICE =
            new IntegrationTestConfigurationService(
                    notificationsQueue,
                    tokenSigner,
                    docAppPrivateKeyJwtSigner,
                    configurationParameters) {

                @Override
                public String getTxmaAuditQueueUrl() {
                    return txmaAuditQueue.getQueueUrl();
                }

                @Override
                public boolean isAuthenticationAttemptsServiceEnabled() {
                    return true;
                }
            };

    private final AuthenticationAttemptsService authenticationService =
            new AuthenticationAttemptsService(CONFIGURATION_SERVICE);

    @BeforeEach
    void setup() throws Json.JsonException {
        authSessionExtension.addSession(SESSION_ID);
        authSessionExtension.addEmailToSession(SESSION_ID, TEST_EMAIL);
        authSessionExtension.addClientIdToSession(SESSION_ID, CLIENT_ID.getValue());
        requestHeaders = createHeaders(SESSION_ID);
        handler = new CheckReAuthUserHandler(CONFIGURATION_SERVICE);
        txmaAuditQueue.clear();
    }

    @Nested
    class SuccessTests {
        @Test
        void shouldReturn200WithSuccessfulCheckReAuthUserRequest() {
            userStore.signUp(TEST_EMAIL, "password-1", SUBJECT);

            authSessionExtension.addRpSectorIdentifierHostToSession(
                    SESSION_ID, INTERNAL_SECTOR_HOST);
            byte[] salt = userStore.addSalt(TEST_EMAIL);
            var expectedPairwiseId =
                    ClientSubjectHelper.calculatePairwiseIdentifier(
                            SUBJECT.getValue(), INTERNAL_SECTOR_HOST, salt);
            var request = new CheckReauthUserRequest(TEST_EMAIL, expectedPairwiseId);
            var response =
                    makeRequest(
                            Optional.of(request),
                            requestHeaders,
                            Collections.emptyMap(),
                            Collections.emptyMap(),
                            Map.of("principalId", expectedPairwiseId));

            assertThat(response, hasStatus(200));

            assertAuditEventExpectations(
                    txmaAuditQueue,
                    List.of(
                            new AuditEventExpectation(AUTH_REAUTH_ACCOUNT_IDENTIFIED)
                                    .withAttribute(RP_PAIRWISE_ID, expectedPairwiseId)));
        }
    }

    @Nested
    class UserNotFoundTests {
        @Test
        void shouldReturn404WhenUserNotFound() {
            userStore.signUp(TEST_EMAIL, "password-1", SUBJECT);

            authSessionExtension.addRpSectorIdentifierHostToSession(
                    SESSION_ID, "randomSectorIDuRI.COM");
            byte[] salt = userStore.addSalt(TEST_EMAIL);
            var expectedPairwiseId =
                    ClientSubjectHelper.calculatePairwiseIdentifier(
                            SUBJECT.getValue(), INTERNAL_SECTOR_HOST, salt);
            var request = new CheckReauthUserRequest(TEST_EMAIL, expectedPairwiseId);
            var response =
                    makeRequest(
                            Optional.of(request),
                            requestHeaders,
                            Collections.emptyMap(),
                            Collections.emptyMap(),
                            Map.of());

            assertThat(response, hasStatus(404));
        }

        @Test
        void shouldReturn404WhenUserNotMatched() {
            userStore.signUp(TEST_EMAIL, "password-1", SUBJECT);

            authSessionExtension.addRpSectorIdentifierHostToSession(
                    SESSION_ID, "randomSectorIDuRI.COM");
            byte[] salt = userStore.addSalt(TEST_EMAIL);
            var expectedPairwiseId =
                    ClientSubjectHelper.calculatePairwiseIdentifier(
                            SUBJECT.getValue(), INTERNAL_SECTOR_HOST, salt);
            var request = new CheckReauthUserRequest(TEST_EMAIL, expectedPairwiseId);
            var response =
                    makeRequest(
                            Optional.of(request),
                            requestHeaders,
                            Collections.emptyMap(),
                            Collections.emptyMap(),
                            Map.of("principalId", expectedPairwiseId));

            assertThat(response, hasStatus(404));
        }
    }

    @Nested
    class LockoutTests {
        void shouldLockoutAfterMaxIncorrectEmailAttempts() {
            setupUser();
            var expectedPairwiseId = setupPairwiseId();

            IntStream.rangeClosed(1, 5)
                    .forEach(
                            i -> {
                                var request =
                                        new CheckReauthUserRequest(
                                                "wrong@example.com", expectedPairwiseId);
                                var response =
                                        makeRequest(
                                                Optional.of(request),
                                                requestHeaders,
                                                Collections.emptyMap(),
                                                Collections.emptyMap(),
                                                Map.of());
                                assertThat(response, hasStatus(404));

                                assertAuditEventExpectations(
                                        txmaAuditQueue,
                                        List.of(
                                                new AuditEventExpectation(
                                                                AUTH_REAUTH_INCORRECT_EMAIL_ENTERED)
                                                        .withAttribute(
                                                                INCORRECT_EMAIL_ATTEMPT_COUNT,
                                                                String.valueOf(i))
                                                        .withAttribute(
                                                                USER_SUPPLIED_EMAIL,
                                                                "wrong@example.com")
                                                        .withAttribute(
                                                                RP_PAIRWISE_ID,
                                                                expectedPairwiseId)));
                            });

            var finalRequest = new CheckReauthUserRequest(TEST_EMAIL, expectedPairwiseId);
            var finalResponse =
                    makeRequest(
                            Optional.of(finalRequest),
                            requestHeaders,
                            Collections.emptyMap(),
                            Collections.emptyMap(),
                            Map.of("principalId", expectedPairwiseId));

            assertThat(finalResponse, hasStatus(400));
            assertThat(
                    authCodeExtension.getAuthenticationAttempt(
                            SUBJECT.getValue(),
                            JourneyType.REAUTHENTICATION,
                            CountType.ENTER_EMAIL),
                    equalTo(6));

            assertAuditEventExpectations(
                    txmaAuditQueue,
                    List.of(
                            new AuditEventExpectation(BASE_REAUTH_FAILED_EXPECTATION)
                                    .withAttribute(INCORRECT_OTP_CODE_ATTEMPT_COUNT, "0")
                                    .withAttribute(RP_PAIRWISE_ID, expectedPairwiseId),
                            new AuditEventExpectation(BASE_INCORRECT_EMAIL_ENTERED_EXPECTATION)
                                    .withAttribute(RP_PAIRWISE_ID, expectedPairwiseId),
                            new AuditEventExpectation(BASE_LIMIT_BREACHED_EXPECTATION)
                                    .withAttribute(RP_PAIRWISE_ID, expectedPairwiseId)));
        }

        @Test
        void shouldLockoutWhenCombinedAttemptsAcrossSubjectIdAndPairwiseIdExceedLimit() {
            setupUser();
            var expectedPairwiseId = setupPairwiseId();

            createEmailAttempts(SUBJECT.getValue(), 3);
            createEmailAttempts(expectedPairwiseId, 2);

            var request = new CheckReauthUserRequest(TEST_EMAIL, expectedPairwiseId);
            var response =
                    makeRequest(
                            Optional.of(request),
                            requestHeaders,
                            Collections.emptyMap(),
                            Collections.emptyMap(),
                            Map.of("principalId", expectedPairwiseId));

            assertThat(response, hasStatus(400));
            assertThat(
                    authCodeExtension.getAuthenticationAttempt(
                            SUBJECT.getValue(),
                            JourneyType.REAUTHENTICATION,
                            CountType.ENTER_EMAIL),
                    equalTo(4));
        }

        @Test
        void should400WhenUserAlreadyHasMaxPasswordAttempts() {
            setupUser();
            var expectedPairwiseId = setupPairwiseId();

            createPasswordAttempts(SUBJECT.getValue(), 6);

            var request = new CheckReauthUserRequest(TEST_EMAIL, expectedPairwiseId);
            var response =
                    makeRequest(
                            Optional.of(request),
                            requestHeaders,
                            Collections.emptyMap(),
                            Collections.emptyMap(),
                            Map.of("principalId", expectedPairwiseId));

            assertThat(response, hasStatus(400));
            assertThat(response, hasJsonBody(ErrorResponse.TOO_MANY_INVALID_REAUTH_ATTEMPTS));
        }
    }

    private void setupUser() {
        setupUser("https://randomSectorIDuRI.COM", "randomSectorIDuRI.COM");
    }

    private void setupUser(String clientUri, String sectorHost) {
        userStore.signUp(TEST_EMAIL, "password-1", SUBJECT);
        authSessionExtension.addRpSectorIdentifierHostToSession(SESSION_ID, sectorHost);
    }

    private String setupPairwiseId() {
        byte[] salt = userStore.addSalt(TEST_EMAIL);
        return ClientSubjectHelper.calculatePairwiseIdentifier(
                SUBJECT.getValue(), INTERNAL_SECTOR_HOST, salt);
    }

    private void createEmailAttempts(String identifier, int count) {
        var ttl = NowHelper.nowPlus(10, ChronoUnit.MINUTES).toInstant().getEpochSecond();
        IntStream.range(0, count)
                .forEach(
                        i ->
                                authCodeExtension.createOrIncrementCount(
                                        identifier,
                                        ttl,
                                        JourneyType.REAUTHENTICATION,
                                        CountType.ENTER_EMAIL));
    }

    private void createPasswordAttempts(String identifier, int count) {
        var ttl = Instant.now().getEpochSecond() + 60L;
        IntStream.range(0, count)
                .forEach(
                        i ->
                                authCodeExtension.createOrIncrementCount(
                                        identifier,
                                        ttl,
                                        JourneyType.REAUTHENTICATION,
                                        CountType.ENTER_PASSWORD));
    }

    private Map<String, String> createHeaders(String sessionId) {
        Map<String, String> headers = new HashMap<>();
        headers.put("Session-Id", sessionId);
        headers.put("X-API-Key", FRONTEND_API_KEY);
        headers.put("Client-Session-Id", CLIENT_SESSION_ID);
        headers.put(TXMA_AUDIT_ENCODED_HEADER, ENCODED_DEVICE_INFORMATION);
        return headers;
    }
}
