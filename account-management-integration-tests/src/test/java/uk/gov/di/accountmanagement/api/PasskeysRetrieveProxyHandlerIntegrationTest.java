package uk.gov.di.accountmanagement.api;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import uk.gov.di.accountmanagement.lambda.PasskeysRetrieveProxyHandler;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;
import uk.org.webcompere.systemstubs.environment.EnvironmentVariables;
import uk.org.webcompere.systemstubs.jupiter.SystemStub;
import uk.org.webcompere.systemstubs.jupiter.SystemStubsExtension;

import java.util.Collections;
import java.util.Map;
import java.util.Optional;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathMatching;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

@ExtendWith(SystemStubsExtension.class)
class PasskeysRetrieveProxyHandlerIntegrationTest extends ApiGatewayHandlerIntegrationTest {
    private static WireMockServer accountDataApiWireMockServer;

    private static final String AUTHORIZATION_HEADER_FIELD = "Authorization";
    private static final String ADAPI_TOKEN_HEADER = "X-ADAPI-AccessToken";

    @SystemStub static EnvironmentVariables environment = new EnvironmentVariables();

    @BeforeEach
    void setup() {
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
    void shouldProxy200ResponseFromAccountDataApi() {
        // Arrange
        handler = new PasskeysRetrieveProxyHandler(TEST_CONFIGURATION_SERVICE);

        var publicSubjectId = "abc";
        var token = "def";
        var adapiResponse =
                """
                {
                  "passkeys": [
                    {
                      "id": "123456",
                      "credential": "credential1",
                      "aaguid": "some-aaguid",
                      "isAttested": true,
                      "signCount": 1,
                      "transports": [],
                      "isBackupEligible": true,
                      "isBackedUp": true,
                      "createdAt": "some-timestamp",
                      "lastUsedAt": "another-timestamp"
                    }
                  ]
                }
                """;

        accountDataApiWireMockServer.stubFor(
                get(urlPathMatching("/accounts/" + publicSubjectId + "/authenticators/passkeys"))
                        .withHeader(AUTHORIZATION_HEADER_FIELD, WireMock.equalTo("Bearer " + token))
                        .willReturn(aResponse().withStatus(200).withBody(adapiResponse)));

        // Act
        var response =
                makeRequest(
                        Optional.empty(),
                        Map.of(ADAPI_TOKEN_HEADER, token),
                        Collections.emptyMap(),
                        Map.of("publicSubjectId", publicSubjectId));

        // Assert
        assertThat(response, hasStatus(200));
        assertThat(response.getBody(), equalTo(adapiResponse));
        accountDataApiWireMockServer.verify(
                1,
                getRequestedFor(
                                urlPathMatching(
                                        "/accounts/"
                                                + publicSubjectId
                                                + "/authenticators/passkeys"))
                        .withHeader(
                                AUTHORIZATION_HEADER_FIELD, WireMock.equalTo("Bearer " + token)));
    }

    @Test
    void shouldProxy500ResponseFromAccountDataApi() {
        // Arrange
        handler = new PasskeysRetrieveProxyHandler(TEST_CONFIGURATION_SERVICE);

        var publicSubjectId = "abc";
        var token = "def";
        var adapiResponse =
                """
                {
                  "code": 5000,
                  "message": "Internal server error"
                }
                """;

        accountDataApiWireMockServer.stubFor(
                get(urlPathMatching("/accounts/" + publicSubjectId + "/authenticators/passkeys"))
                        .withHeader(AUTHORIZATION_HEADER_FIELD, WireMock.equalTo("Bearer " + token))
                        .willReturn(aResponse().withStatus(500).withBody(adapiResponse)));

        // Act
        var response =
                makeRequest(
                        Optional.empty(),
                        Map.of(ADAPI_TOKEN_HEADER, token),
                        Collections.emptyMap(),
                        Map.of("publicSubjectId", publicSubjectId));

        // Assert
        assertThat(response, hasStatus(500));
        assertThat(response.getBody(), equalTo(adapiResponse));
        accountDataApiWireMockServer.verify(
                1,
                getRequestedFor(
                                urlPathMatching(
                                        "/accounts/"
                                                + publicSubjectId
                                                + "/authenticators/passkeys"))
                        .withHeader(
                                AUTHORIZATION_HEADER_FIELD, WireMock.equalTo("Bearer " + token)));
    }
}
