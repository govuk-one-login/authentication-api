package uk.gov.di.authentication.api;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.frontendapi.entity.SignupRequest;
import uk.gov.di.authentication.frontendapi.lambda.SignUpHandler;
import uk.gov.di.authentication.shared.entity.BaseAPIResponse;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.CREATE_ACCOUNT;
import static uk.gov.di.authentication.shared.entity.SessionState.EMAIL_CODE_VERIFIED;
import static uk.gov.di.authentication.shared.entity.SessionState.TWO_FACTOR_REQUIRED;
import static uk.gov.di.authentication.sharedtest.helper.AuditAssertionsHelper.assertEventTypesReceived;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

public class SignupIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    @BeforeEach
    void setup() {
        handler = new SignUpHandler(TEST_CONFIGURATION_SERVICE);
    }

    @Test
    void shouldReturn200WhenValidSignUpRequest() throws IOException {
        String sessionId = redis.createSession();

        redis.setSessionState(sessionId, EMAIL_CODE_VERIFIED);

        Map<String, String> headers = new HashMap<>();
        headers.put("Session-Id", sessionId);
        headers.put("X-API-Key", FRONTEND_API_KEY);

        var response =
                makeRequest(
                        Optional.of(
                                new SignupRequest(
                                        "joe.bloggs+5@digital.cabinet-office.gov.uk",
                                        "password-1")),
                        headers,
                        Map.of());

        assertThat(response, hasStatus(200));

        BaseAPIResponse BaseAPIResponse =
                objectMapper.readValue(response.getBody(), BaseAPIResponse.class);
        assertThat(BaseAPIResponse.getSessionState(), equalTo(TWO_FACTOR_REQUIRED));
        assertTrue(userStore.userExists("joe.bloggs+5@digital.cabinet-office.gov.uk"));

        assertEventTypesReceived(auditTopic, List.of(CREATE_ACCOUNT));
    }
}
