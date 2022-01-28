package uk.gov.di.authentication.api;

import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.oidc.lambda.IdentityHandler;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;

import java.util.Map;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

public class IdentityIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    @BeforeEach
    void setup() {
        handler = new IdentityHandler(TEST_CONFIGURATION_SERVICE);
    }

    @Test
    void shouldReturn204WhenCallingIdentityLambda() {

        var response =
                makeRequest(
                        Optional.empty(),
                        Map.of("Authorization", new BearerAccessToken().toAuthorizationHeader()),
                        Map.of());

        assertThat(response, hasStatus(204));
    }
}
