package uk.gov.di.authentication.api;

import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import org.junit.jupiter.api.BeforeEach;
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
import uk.gov.di.orchestration.sharedtest.helper.KeyPairHelper;

import java.net.URI;
import java.security.KeyPair;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.IntStream;

import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_REAUTH_FAILED;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_REAUTH_INCORRECT_EMAIL_ENTERED;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_REAUTH_INCORRECT_EMAIL_LIMIT_BREACHED;
import static uk.gov.di.authentication.shared.helpers.TxmaAuditHelper.TXMA_AUDIT_ENCODED_HEADER;
import static uk.gov.di.authentication.sharedtest.helper.AuditAssertionsHelper.assertTxmaAuditEventsReceived;
import static uk.gov.di.orchestration.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.orchestration.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

public class CheckReAuthUserHandlerIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    private static final String TEST_EMAIL = "joe.bloggs@digital.cabinet-office.gov.uk";
    private static final String INTERNAL_SECTOR_HOST = "test.account.gov.uk";
    private static final String CLIENT_SESSION_ID = "a-client-session-id";
    private static final String CLIENT_NAME = "some-client-name";
    private static final ClientID CLIENT_ID = new ClientID("test-client");
    private static final Subject SUBJECT = new Subject();
    private final KeyPair keyPair = KeyPairHelper.GENERATE_RSA_KEY_PAIR();
    private static final URI REDIRECT_URI =
            URI.create(System.getenv("STUB_RELYING_PARTY_REDIRECT_URI"));
    private static final String SESSION_ID = "test-session-id";
    private Map<String, String> requestHeaders;

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

    @Test
    void shouldReturn200WithSuccessfulCheckReAuthUserRequest() {
        userStore.signUp(TEST_EMAIL, "password-1", SUBJECT);
        registerClient("https://" + INTERNAL_SECTOR_HOST);
        authSessionExtension.addRpSectorIdentifierHostToSession(SESSION_ID, INTERNAL_SECTOR_HOST);
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
    }

    @Test
    void shouldReturn404WhenUserNotFound() {
        userStore.signUp(TEST_EMAIL, "password-1", SUBJECT);
        registerClient("https://randomSectorIDuRI.COM");
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
        registerClient("https://randomSectorIDuRI.COM");
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

    @Test
    void shouldReturn400WhenUserEnteredInvalidEmailTooManyTimes() {
        userStore.signUp(TEST_EMAIL, "password-1", SUBJECT);
        registerClient("https://randomSectorIDuRI.COM");
        authSessionExtension.addRpSectorIdentifierHostToSession(
                SESSION_ID, "randomSectorIDuRI.COM");
        var maxRetriesAllowed = 6;
        int count = maxRetriesAllowed - 1;
        while (count-- > 0) {
            authenticationService.createOrIncrementCount(
                    SUBJECT.getValue(),
                    NowHelper.nowPlus(10, ChronoUnit.MINUTES).toInstant().getEpochSecond(),
                    JourneyType.REAUTHENTICATION,
                    CountType.ENTER_EMAIL);
        }

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

        assertThat(response, hasStatus(400));
        assertThat(
                authCodeExtension.getAuthenticationAttempt(
                        SUBJECT.getValue(), JourneyType.REAUTHENTICATION, CountType.ENTER_EMAIL),
                equalTo(maxRetriesAllowed));
        assertTxmaAuditEventsReceived(
                txmaAuditQueue,
                List.of(
                        AUTH_REAUTH_FAILED,
                        AUTH_REAUTH_INCORRECT_EMAIL_ENTERED,
                        AUTH_REAUTH_INCORRECT_EMAIL_LIMIT_BREACHED));
    }

    @Test
    void shouldReturn400WhenUserEnteredInvalidEmailTooManyTimesAcrossRpPairwiseIdAndSubjectId() {
        userStore.signUp(TEST_EMAIL, "password-1", SUBJECT);
        registerClient("https://randomSectorIDuRI.COM");
        authSessionExtension.addRpSectorIdentifierHostToSession(
                SESSION_ID, "randomSectorIDuRI.COM");
        byte[] salt = userStore.addSalt(TEST_EMAIL);
        var expectedPairwiseId =
                ClientSubjectHelper.calculatePairwiseIdentifier(
                        SUBJECT.getValue(), INTERNAL_SECTOR_HOST, salt);

        var subjectIdCount = 3;
        var rpPairwiseIdCount = 2;
        for (int i = 0; i < subjectIdCount; i++) {
            authenticationService.createOrIncrementCount(
                    SUBJECT.getValue(),
                    NowHelper.nowPlus(10, ChronoUnit.MINUTES).toInstant().getEpochSecond(),
                    JourneyType.REAUTHENTICATION,
                    CountType.ENTER_EMAIL);
        }
        for (int i = 0; i < rpPairwiseIdCount; i++) {
            authenticationService.createOrIncrementCount(
                    expectedPairwiseId,
                    NowHelper.nowPlus(10, ChronoUnit.MINUTES).toInstant().getEpochSecond(),
                    JourneyType.REAUTHENTICATION,
                    CountType.ENTER_EMAIL);
        }

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
                        SUBJECT.getValue(), JourneyType.REAUTHENTICATION, CountType.ENTER_EMAIL),
                equalTo(subjectIdCount + 1));
        assertTxmaAuditEventsReceived(
                txmaAuditQueue,
                List.of(
                        AUTH_REAUTH_FAILED,
                        AUTH_REAUTH_INCORRECT_EMAIL_ENTERED,
                        AUTH_REAUTH_INCORRECT_EMAIL_LIMIT_BREACHED));
    }

    @Test
    void shouldReturn400WhenUserHasExceededMaxPasswordRetries() {
        userStore.signUp(TEST_EMAIL, "password-1", SUBJECT);
        registerClient("https://randomSectorIDuRI.COM");
        authSessionExtension.addRpSectorIdentifierHostToSession(
                SESSION_ID, "randomSectorIDuRI.COM");

        var ttl = Instant.now().getEpochSecond() + 60L;
        IntStream.range(0, 6)
                .forEach(
                        i ->
                                authCodeExtension.createOrIncrementCount(
                                        SUBJECT.getValue(),
                                        ttl,
                                        JourneyType.REAUTHENTICATION,
                                        CountType.ENTER_PASSWORD));

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

        assertThat(response, hasStatus(400));
        assertThat(response, hasJsonBody(ErrorResponse.ERROR_1057));
    }

    @Test
    void shouldReturn400WhenUserHasExceededMaxEmailRetriesAcrossSubjectIdAndPairwiseId() {
        userStore.signUp(TEST_EMAIL, "password-1", SUBJECT);
        registerClient("https://randomSectorIDuRI.COM");
        authSessionExtension.addRpSectorIdentifierHostToSession(
                SESSION_ID, "randomSectorIDuRI.COM");
        byte[] salt = userStore.addSalt(TEST_EMAIL);
        var expectedPairwiseId =
                ClientSubjectHelper.calculatePairwiseIdentifier(
                        SUBJECT.getValue(), INTERNAL_SECTOR_HOST, salt);

        var ttl = Instant.now().getEpochSecond() + 60L;
        IntStream.range(0, 3)
                .forEach(
                        i -> {
                            authCodeExtension.createOrIncrementCount(
                                    SUBJECT.getValue(),
                                    ttl,
                                    JourneyType.REAUTHENTICATION,
                                    CountType.ENTER_EMAIL);
                            authCodeExtension.createOrIncrementCount(
                                    expectedPairwiseId,
                                    ttl,
                                    JourneyType.REAUTHENTICATION,
                                    CountType.ENTER_EMAIL);
                        });

        var request = new CheckReauthUserRequest(TEST_EMAIL, expectedPairwiseId);
        var response =
                makeRequest(
                        Optional.of(request),
                        requestHeaders,
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        Map.of("principalId", expectedPairwiseId));

        assertThat(response, hasStatus(400));
        assertThat(response, hasJsonBody(ErrorResponse.ERROR_1057));
    }

    private void registerClient(String sectorIdentifierUri) {
        clientStore.registerClient(
                CLIENT_ID.getValue(),
                CLIENT_NAME,
                singletonList(REDIRECT_URI.toString()),
                singletonList(TEST_EMAIL),
                new Scope(OIDCScopeValue.OPENID).toStringList(),
                Base64.getMimeEncoder().encodeToString(keyPair.getPublic().getEncoded()),
                singletonList("http://localhost/post-redirect-logout"),
                "http://example.com",
                String.valueOf(uk.gov.di.orchestration.shared.entity.ServiceType.MANDATORY),
                sectorIdentifierUri,
                "pairwise");
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
