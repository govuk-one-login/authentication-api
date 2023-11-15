package uk.gov.di.authentication.api;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.frontendapi.lambda.AccountInterventionsHandler;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;

import java.util.Map;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

public class AccountInterventionsHandlerIntegrationTest extends ApiGatewayHandlerIntegrationTest {
    @BeforeEach
    void setup() throws Json.JsonException {
        handler = new AccountInterventionsHandler();
    }

    @Test
    void shouldReturn200StatusAndCheckBody() {
        var response = makeRequest(Optional.empty(), Map.of(), Map.of());
        assertThat(response, hasStatus(200));
        assertTrue(response.getBody().contains("Hello world"));
    }
}
