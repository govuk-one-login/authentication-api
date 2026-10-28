package uk.gov.di.accountmanagement.api;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import uk.gov.di.accountmanagement.lambda.AccountDeleteProxyHandler;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;
import uk.org.webcompere.systemstubs.environment.EnvironmentVariables;
import uk.org.webcompere.systemstubs.jupiter.SystemStub;
import uk.org.webcompere.systemstubs.jupiter.SystemStubsExtension;

import java.util.Collections;
import java.util.Map;
import java.util.Optional;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.delete;
import static com.github.tomakehurst.wiremock.client.WireMock.deleteRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

@ExtendWith(SystemStubsExtension.class)
class AccountDeleteProxyHandlerIntegrationTest extends ApiGatewayHandlerIntegrationTest {
    private WireMockServer accountDataApiWireMockServer;

    private static final String AUTHORIZATION_HEADER_FIELD = "Authorization";
    private static final String ADAPI_TOKEN_HEADER = "X-ADAPI-AccessToken";
    private static final String PUBLIC_SUBJECT_ID = "abc";
    private static final String TOKEN = "def";
    private static final String REQUEST_BODY =
            """
            {
              "clientId": "amc",
              "reason": "USER_INITIATED"
            }
            """;

    @SystemStub static EnvironmentVariables environment = new EnvironmentVariables();

    @BeforeEach
    void setup() {
        accountDataApiWireMockServer =
                new WireMockServer(WireMockConfiguration.wireMockConfig().dynamicPort());
        accountDataApiWireMockServer.start();

        environment.set(
                "ACCOUNT_DATA_API_URI", "http://localhost:" + accountDataApiWireMockServer.port());

        handler = new AccountDeleteProxyHandler(TEST_CONFIGURATION_SERVICE);
    }

    @AfterEach
    void tearDown() {
        if (accountDataApiWireMockServer != null) {
            accountDataApiWireMockServer.stop();
        }
    }

    @Test
    void shouldProxy204ResponseFromAccountDataApi() {
        stubAccountDataApiDelete(204, "");

        var response = makeAccountDeleteRequest();

        assertThat(response, hasStatus(204));
        verifyAccountDataApiDeleteCalledOnce();
    }

    @Test
    void shouldProxy404ResponseFromAccountDataApi() {
        var adapiResponse =
                """
                {
                  "code": 1056,
                  "message": "User not found or no match"
                }
                """;
        stubAccountDataApiDelete(404, adapiResponse);

        var response = makeAccountDeleteRequest();

        assertThat(response, hasStatus(404));
        assertThat(response.getBody(), equalTo(adapiResponse));
        verifyAccountDataApiDeleteCalledOnce();
    }

    private void stubAccountDataApiDelete(int statusCode, String body) {
        accountDataApiWireMockServer.stubFor(
                delete(urlPathEqualTo("/accounts/" + PUBLIC_SUBJECT_ID))
                        .withHeader(AUTHORIZATION_HEADER_FIELD, WireMock.equalTo("Bearer " + TOKEN))
                        .willReturn(aResponse().withStatus(statusCode).withBody(body)));
    }

    private APIGatewayProxyResponseEvent makeAccountDeleteRequest() {
        return makeRequest(
                Optional.<Object>of(REQUEST_BODY),
                Map.of(ADAPI_TOKEN_HEADER, TOKEN),
                Collections.emptyMap(),
                Map.of("publicSubjectId", PUBLIC_SUBJECT_ID));
    }

    private void verifyAccountDataApiDeleteCalledOnce() {
        accountDataApiWireMockServer.verify(
                1,
                deleteRequestedFor(urlPathEqualTo("/accounts/" + PUBLIC_SUBJECT_ID))
                        .withHeader(
                                AUTHORIZATION_HEADER_FIELD, WireMock.equalTo("Bearer " + TOKEN)));
    }
}
