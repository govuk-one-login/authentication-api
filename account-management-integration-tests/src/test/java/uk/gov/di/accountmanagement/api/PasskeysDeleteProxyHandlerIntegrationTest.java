package uk.gov.di.accountmanagement.api;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import uk.gov.di.accountmanagement.lambda.PasskeysDeleteProxyHandler;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;
import uk.org.webcompere.systemstubs.environment.EnvironmentVariables;
import uk.org.webcompere.systemstubs.jupiter.SystemStub;
import uk.org.webcompere.systemstubs.jupiter.SystemStubsExtension;

import java.util.Collections;
import java.util.Map;
import java.util.Optional;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.delete;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathMatching;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

@ExtendWith(SystemStubsExtension.class)
class PasskeysDeleteProxyHandlerIntegrationTest extends ApiGatewayHandlerIntegrationTest {
    private static WireMockServer accountDataApiWireMockServer;

    @SystemStub static EnvironmentVariables environment = new EnvironmentVariables();

    @BeforeEach
    void setUp() {
        accountDataApiWireMockServer =
                new WireMockServer(WireMockConfiguration.wireMockConfig().dynamicPort());
        accountDataApiWireMockServer.start();

        environment.set(
                "ACCOUNT_DATA_API_URI", "http://localhost:" + accountDataApiWireMockServer.port());
    }

    @AfterAll
    static void tearDown() {
        if (accountDataApiWireMockServer != null) {
            accountDataApiWireMockServer.stop();
        }
    }

    @Test
    void shouldProxy204ResponseFromAccountDataApi() {
        // Arrange
        handler = new PasskeysDeleteProxyHandler(TEST_CONFIGURATION_SERVICE);

        var publicSubjectId = "abc";
        var passkeyId = "def";

        accountDataApiWireMockServer.stubFor(
                delete(
                                urlPathMatching(
                                        "/accounts/"
                                                + publicSubjectId
                                                + "/authenticators/passkeys/"
                                                + passkeyId))
                        .willReturn(aResponse().withStatus(204)));

        // Act
        var response =
                makeRequest(
                        Optional.empty(),
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        Map.of("publicSubjectId", publicSubjectId, "passkeyIdentifier", passkeyId),
                        Collections.emptyMap(),
                        Optional.of("delete"));

        // Assert
        assertThat(response, hasStatus(204));
    }

    @Test
    void shouldProxy404ResponseFromAccountDataApi() {
        // Arrange
        handler = new PasskeysDeleteProxyHandler(TEST_CONFIGURATION_SERVICE);

        var publicSubjectId = "abc";
        var passkeyId = "def";
        var adapiResponse =
                """
                {
                  "code": 4040,
                  "message": "Passkey not found"
                }
                """;

        accountDataApiWireMockServer.stubFor(
                delete(
                                urlPathMatching(
                                        "/accounts/"
                                                + publicSubjectId
                                                + "/authenticators/passkeys/"
                                                + passkeyId))
                        .willReturn(aResponse().withStatus(404).withBody(adapiResponse)));

        // Act
        var response =
                makeRequest(
                        Optional.empty(),
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        Map.of("publicSubjectId", publicSubjectId, "passkeyIdentifier", passkeyId),
                        Collections.emptyMap(),
                        Optional.of("delete"));

        // Assert
        assertThat(response, hasStatus(404));
        assertThat(response.getBody(), equalTo(adapiResponse));
    }

    @Test
    void shouldProxy500ResponseFromAccountDataApi() {
        // Arrange
        handler = new PasskeysDeleteProxyHandler(TEST_CONFIGURATION_SERVICE);

        var publicSubjectId = "abc";
        var passkeyId = "def";
        var adapiResponse =
                """
                {
                  "code": 5000,
                  "message": "Internal server error"
                }
                """;

        accountDataApiWireMockServer.stubFor(
                delete(
                                urlPathMatching(
                                        "/accounts/"
                                                + publicSubjectId
                                                + "/authenticators/passkeys/"
                                                + passkeyId))
                        .willReturn(aResponse().withStatus(500).withBody(adapiResponse)));

        // Act
        var response =
                makeRequest(
                        Optional.empty(),
                        Collections.emptyMap(),
                        Collections.emptyMap(),
                        Map.of("publicSubjectId", publicSubjectId, "passkeyIdentifier", passkeyId),
                        Collections.emptyMap(),
                        Optional.of("delete"));

        // Assert
        assertThat(response, hasStatus(500));
        assertThat(response.getBody(), equalTo(adapiResponse));
    }
}
