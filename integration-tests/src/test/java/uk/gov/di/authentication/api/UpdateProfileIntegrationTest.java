package uk.gov.di.authentication.api;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.frontendapi.entity.UpdateProfileRequest;
import uk.gov.di.authentication.frontendapi.lambda.UpdateProfileHandler;
import uk.gov.di.authentication.shared.entity.ServiceType;
import uk.gov.di.authentication.shared.helpers.IdGenerator;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_UPDATE_PROFILE_REQUEST_RECEIVED;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_UPDATE_PROFILE_TERMS_CONDS_ACCEPTANCE;
import static uk.gov.di.authentication.frontendapi.entity.UpdateProfileType.UPDATE_TERMS_CONDS;
import static uk.gov.di.authentication.sharedtest.helper.AuditAssertionsHelper.assertTxmaAuditEventsReceived;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

public class UpdateProfileIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    private static final String EMAIL_ADDRESS = "test@test.com";
    private static final String CLIENT_ID = "test-id";

    @BeforeEach
    void setup() {
        handler =
                new UpdateProfileHandler(
                        TXMA_ENABLED_CONFIGURATION_SERVICE, redisConnectionService);
        txmaAuditQueue.clear();
    }

    @Test
    void shouldCallUpdateProfileToApproveTermsAndConditionsAndReturn204()
            throws Json.JsonException {
        String sessionId = redis.createSession();
        String clientSessionId = IdGenerator.generate();
        setUpTest(sessionId);

        UpdateProfileRequest request =
                new UpdateProfileRequest(EMAIL_ADDRESS, UPDATE_TERMS_CONDS, String.valueOf(true));

        var response =
                makeRequest(
                        Optional.of(request),
                        constructFrontendHeaders(sessionId, clientSessionId),
                        Map.of());

        assertThat(response, hasStatus(204));
        assertTxmaAuditEventsReceived(
                txmaAuditQueue,
                List.of(
                        AUTH_UPDATE_PROFILE_REQUEST_RECEIVED,
                        AUTH_UPDATE_PROFILE_TERMS_CONDS_ACCEPTANCE));
    }

    private void setUpTest(String sessionId) {
        authSessionStore.addSession(sessionId);
        authSessionStore.addEmailToSession(sessionId, EMAIL_ADDRESS);
        clientStore.registerClient(
                CLIENT_ID,
                "test-client",
                singletonList("redirect-url"),
                singletonList(EMAIL_ADDRESS),
                List.of("openid", "email"),
                "public-key",
                singletonList("http://localhost/post-redirect-logout"),
                "http://example.com",
                String.valueOf(ServiceType.MANDATORY),
                "https://test.com",
                "public");
        userStore.signUp(EMAIL_ADDRESS, "password");
    }
}
