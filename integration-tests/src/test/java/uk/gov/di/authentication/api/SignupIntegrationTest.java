package uk.gov.di.authentication.api;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.frontendapi.entity.SignupRequest;
import uk.gov.di.authentication.frontendapi.lambda.SignUpHandler;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;
import uk.gov.di.authentication.sharedtest.extensions.AuthSessionExtension;
import uk.gov.di.authentication.sharedtest.extensions.CommonPasswordsExtension;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_CREATE_ACCOUNT;
import static uk.gov.di.authentication.shared.helpers.TxmaAuditHelper.TXMA_AUDIT_ENCODED_HEADER;
import static uk.gov.di.authentication.sharedtest.helper.AuditAssertionsHelper.assertTxmaAuditEventsReceived;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

public class SignupIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    private static final String CLIENT_ID = "test-client-id";
    public static final String CLIENT_SESSION_ID = "a-client-session-id";
    public static final String ENCODED_DEVICE_INFORMATION =
            "R21vLmd3QilNKHJsaGkvTFxhZDZrKF44SStoLFsieG0oSUY3aEhWRVtOMFRNMVw1dyInKzB8OVV5N09hOi8kLmlLcWJjJGQiK1NPUEJPPHBrYWJHP358NDg2ZDVc";
    private static final String SESSION_ID = "session-id";
    private static final String SECTOR_IDENTIFIER_HOST = "test.com";
    private final AuthSessionExtension authSessionExtension = new AuthSessionExtension();

    @BeforeEach
    void setup() throws Json.JsonException {
        handler = new SignUpHandler(TXMA_ENABLED_CONFIGURATION_SERVICE);
        txmaAuditQueue.clear();
    }

    @Test
    void shouldReturn200WhenValidSignUpRequest() {
        withAuthSession();

        Map<String, String> headers = new HashMap<>();
        headers.put("Session-Id", SESSION_ID);
        headers.put("Client-Session-Id", CLIENT_SESSION_ID);
        headers.put("X-API-Key", FRONTEND_API_KEY);
        headers.put(TXMA_AUDIT_ENCODED_HEADER, ENCODED_DEVICE_INFORMATION);

        var response =
                makeRequest(
                        Optional.of(
                                new SignupRequest(
                                        "joe.bloggs+5@digital.cabinet-office.gov.uk",
                                        "password-1")),
                        headers,
                        Map.of());

        assertThat(response, hasStatus(200));
        assertTrue(
                Objects.nonNull(
                        authSessionExtension
                                .getSession(SESSION_ID)
                                .orElseThrow()
                                .getInternalCommonSubjectId()));
        assertTrue(userStore.userExists("joe.bloggs+5@digital.cabinet-office.gov.uk"));
        assertThat(authSessionExtension.getSession(SESSION_ID).isPresent(), equalTo(true));
        assertThat(
                authSessionExtension.getSession(SESSION_ID).get().getIsNewAccount(),
                equalTo(AuthSessionItem.AccountState.NEW));
        assertTxmaAuditEventsReceived(txmaAuditQueue, List.of(AUTH_CREATE_ACCOUNT));
    }

    @Test
    void shouldReturn400WhenCommonPassword() throws Json.JsonException {
        withAuthSession();

        Map<String, String> headers = new HashMap<>();
        headers.put("Session-Id", SESSION_ID);
        headers.put("Client-Session-Id", CLIENT_SESSION_ID);
        headers.put("X-API-Key", FRONTEND_API_KEY);
        headers.put(TXMA_AUDIT_ENCODED_HEADER, ENCODED_DEVICE_INFORMATION);

        var response =
                makeRequest(
                        Optional.of(
                                new SignupRequest(
                                        "joe.bloggs+common-password@digital.cabinet-office.gov.uk",
                                        CommonPasswordsExtension.TEST_COMMON_PASSWORD)),
                        headers,
                        Map.of());

        assertThat(response, hasStatus(400));
        assertTrue(response.getBody().contains(ErrorResponse.PW_TOO_COMMON.getMessage()));
    }

    @Test
    void shouldReturn400WhenNoAuthSessionPresent() {
        Map<String, String> headers = new HashMap<>();
        headers.put("Session-Id", SESSION_ID);
        headers.put("Client-Session-Id", CLIENT_SESSION_ID);
        headers.put("X-API-Key", FRONTEND_API_KEY);
        headers.put(TXMA_AUDIT_ENCODED_HEADER, ENCODED_DEVICE_INFORMATION);

        var response =
                makeRequest(
                        Optional.of(
                                new SignupRequest(
                                        "joe.bloggs+5@digital.cabinet-office.gov.uk",
                                        "password-1")),
                        headers,
                        Map.of());

        assertThat(response, hasStatus(400));
        assertThat(response, hasJsonBody(ErrorResponse.SESSION_ID_MISSING));
    }

    private void withAuthSession() {
        authSessionExtension.addSession(SESSION_ID);
        authSessionExtension.addClientIdToSession(SESSION_ID, CLIENT_ID);
        authSessionExtension.addRpSectorIdentifierHostToSession(SESSION_ID, SECTOR_IDENTIFIER_HOST);
    }
}
