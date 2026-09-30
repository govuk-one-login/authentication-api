package uk.gov.di.accountmanagement.api;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import uk.gov.di.accountmanagement.entity.NotifyRequest;
import uk.gov.di.accountmanagement.lambda.PasskeysDeleteProxyHandler;
import uk.gov.di.authentication.shared.helpers.LocaleHelper;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;
import uk.org.webcompere.systemstubs.environment.EnvironmentVariables;
import uk.org.webcompere.systemstubs.jupiter.SystemStub;
import uk.org.webcompere.systemstubs.jupiter.SystemStubsExtension;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.delete;
import static com.github.tomakehurst.wiremock.client.WireMock.deleteRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathMatching;
import static java.lang.String.format;
import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static uk.gov.di.accountmanagement.domain.AccountManagementAuditableEvent.AUTH_PASSKEY_DELETE_SUCCESSFUL;
import static uk.gov.di.accountmanagement.entity.NotificationType.PASSKEY_DELETED_NONE_REMAINING;
import static uk.gov.di.accountmanagement.testsupport.helpers.NotificationAssertionHelper.assertNotificationsReceived;
import static uk.gov.di.authentication.sharedtest.helper.AuditAssertionsHelper.assertTxmaAuditEventsReceived;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

@ExtendWith(SystemStubsExtension.class)
class PasskeysDeleteProxyHandlerIntegrationTest extends ApiGatewayHandlerIntegrationTest {
    private static WireMockServer accountDataApiWireMockServer;

    private static final String TEST_EMAIL = "joe.bloggs@digital.cabinet-office.gov.uk";
    private static final String TEST_PASSWORD = "password";
    private static final String PASSKEY_ID = "abcd123456";
    private static final String passkeyRetrieveResponse =
            format(
                    """
                    {
                      "passkeys": [
                        {
                          "id": "%s",
                          "credential": "credential1",
                          "aaguid": "some-aaguid",
                          "isAttested": true,
                          "signCount": 1,
                          "transports": [],
                          "isBackUpEligible": true,
                          "isBackedUp": true,
                          "createdAt": "some-timestamp",
                          "lastUsedAt": "another-timestamp"
                        }
                      ]
                    }
                    """,
                    PASSKEY_ID);

    private static final String TEST_CLIENT_ID = "test-client-id";

    @SystemStub static EnvironmentVariables environment = new EnvironmentVariables();

    @BeforeEach
    void setUp() {
        accountDataApiWireMockServer =
                new WireMockServer(WireMockConfiguration.wireMockConfig().dynamicPort());
        accountDataApiWireMockServer.start();

        environment.set(
                "ACCOUNT_DATA_API_URI", "http://localhost:" + accountDataApiWireMockServer.port());

        notificationsQueue.clear();
        txmaAuditQueue.clear();
    }

    @AfterAll
    static void tearDown() {
        if (accountDataApiWireMockServer != null) {
            accountDataApiWireMockServer.stop();
        }
    }

    @Test
    void shouldProxy204ResponseFromAccountDataApiAndSendSuccessAuditEvent() {
        // Arrange
        var publicSubjectId = userStore.signUp(TEST_EMAIL, TEST_PASSWORD);
        userStore.addSalt(TEST_EMAIL);
        handler =
                new PasskeysDeleteProxyHandler(
                        supportPasskeysAndTxmaEnabledConfigurationService(
                                "http://localhost:" + accountDataApiWireMockServer.port()));

        var token = "hij";

        accountDataApiWireMockServer.stubFor(
                delete(
                                urlPathMatching(
                                        "/accounts/"
                                                + publicSubjectId
                                                + "/authenticators/passkeys/"
                                                + PASSKEY_ID))
                        .withHeader("Authorization", WireMock.equalTo("Bearer " + token))
                        .willReturn(aResponse().withStatus(204)));

        accountDataApiWireMockServer.stubFor(
                get(urlPathMatching("/accounts/" + publicSubjectId + "/authenticators/passkeys"))
                        .willReturn(aResponse().withStatus(200).withBody(passkeyRetrieveResponse)));

        // Act
        var response =
                makeRequest(
                        Optional.empty(),
                        Map.of("X-ADAPI-AccessToken", token),
                        Collections.emptyMap(),
                        Map.of("publicSubjectId", publicSubjectId, "passkeyIdentifier", PASSKEY_ID),
                        Map.ofEntries(Map.entry("clientId", TEST_CLIENT_ID)),
                        Optional.of("delete"));

        // Assert
        assertThat(response, hasStatus(204));
        accountDataApiWireMockServer.verify(
                1,
                deleteRequestedFor(
                                urlPathMatching(
                                        "/accounts/"
                                                + publicSubjectId
                                                + "/authenticators/passkeys/"
                                                + PASSKEY_ID))
                        .withHeader("Authorization", WireMock.equalTo("Bearer " + token)));

        List<String> rawEvents =
                assertTxmaAuditEventsReceived(
                        txmaAuditQueue, List.of(AUTH_PASSKEY_DELETE_SUCCESSFUL), false);
        assertThatJson(rawEvents.get(0))
                .node("restricted.passkey")
                .isEqualTo(
                        format(
                                """
                        {
                          "passkey_credential_id": "%s",
                          "passkey_aaguid": "some-aaguid",
                          "passkey_credential_device_type": "multi-device"
                        }
                        """,
                                PASSKEY_ID));
    }

    @Test
    void shouldSendPasskeyDeletedEmailNotification() {
        // Arrange
        var publicSubjectId = userStore.signUp(TEST_EMAIL, TEST_PASSWORD);
        userStore.addSalt(TEST_EMAIL);
        handler =
                new PasskeysDeleteProxyHandler(
                        supportPasskeysAndTxmaEnabledConfigurationService(
                                "http://localhost:" + accountDataApiWireMockServer.port()));

        var passkeyId = "def";
        var token = "hij";

        accountDataApiWireMockServer.stubFor(
                delete(
                                urlPathMatching(
                                        "/accounts/"
                                                + publicSubjectId
                                                + "/authenticators/passkeys/"
                                                + passkeyId))
                        .withHeader("Authorization", WireMock.equalTo("Bearer " + token))
                        .willReturn(aResponse().withStatus(204)));

        var passkeyRetrieveResponse =
                format(
                        """
                        {
                          "passkeys": [
                            {
                              "id": "%s",
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
                        """,
                        passkeyId);
        accountDataApiWireMockServer.stubFor(
                get(urlPathMatching("/accounts/" + publicSubjectId + "/authenticators/passkeys"))
                        .willReturn(aResponse().withStatus(200).withBody(passkeyRetrieveResponse)));

        // Act
        var response =
                makeRequest(
                        Optional.empty(),
                        Map.of("X-ADAPI-AccessToken", token),
                        Collections.emptyMap(),
                        Map.of("publicSubjectId", publicSubjectId, "passkeyIdentifier", passkeyId),
                        Map.ofEntries(Map.entry("clientId", TEST_CLIENT_ID)),
                        Optional.of("delete"));

        // Assert
        assertThat(response, hasStatus(204));
        accountDataApiWireMockServer.verify(
                1,
                deleteRequestedFor(
                                urlPathMatching(
                                        "/accounts/"
                                                + publicSubjectId
                                                + "/authenticators/passkeys/"
                                                + passkeyId))
                        .withHeader("Authorization", WireMock.equalTo("Bearer " + token)));
        assertNotificationsReceived(
                notificationsQueue,
                List.of(
                        new NotifyRequest(
                                TEST_EMAIL,
                                PASSKEY_DELETED_NONE_REMAINING,
                                LocaleHelper.SupportedLanguage.EN)));
    }

    @Test
    void shouldProxy404ResponseFromAccountDataApi() {
        // Arrange
        var publicSubjectId = userStore.signUp(TEST_EMAIL, TEST_PASSWORD);
        userStore.addSalt(TEST_EMAIL);
        handler =
                new PasskeysDeleteProxyHandler(
                        supportPasskeysAndTxmaEnabledConfigurationService(
                                "http://localhost:" + accountDataApiWireMockServer.port()));

        var passkeyId = "def";
        var token = "hij";
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
                        .withHeader("Authorization", WireMock.equalTo("Bearer " + token))
                        .willReturn(aResponse().withStatus(404).withBody(adapiResponse)));

        accountDataApiWireMockServer.stubFor(
                get(urlPathMatching("/accounts/" + publicSubjectId + "/authenticators/passkeys"))
                        .willReturn(aResponse().withStatus(200).withBody(passkeyRetrieveResponse)));

        // Act
        var response =
                makeRequest(
                        Optional.empty(),
                        Map.of("X-ADAPI-AccessToken", token),
                        Collections.emptyMap(),
                        Map.of("publicSubjectId", publicSubjectId, "passkeyIdentifier", passkeyId),
                        Map.ofEntries(Map.entry("clientId", TEST_CLIENT_ID)),
                        Optional.of("delete"));

        // Assert
        assertThat(response, hasStatus(404));
        assertThat(response.getBody(), equalTo(adapiResponse));
        accountDataApiWireMockServer.verify(
                1,
                deleteRequestedFor(
                                urlPathMatching(
                                        "/accounts/"
                                                + publicSubjectId
                                                + "/authenticators/passkeys/"
                                                + passkeyId))
                        .withHeader("Authorization", WireMock.equalTo("Bearer " + token)));
    }

    @Test
    void shouldProxy500ResponseFromAccountDataApi() {
        // Arrange
        var publicSubjectId = userStore.signUp(TEST_EMAIL, TEST_PASSWORD);
        userStore.addSalt(TEST_EMAIL);
        handler =
                new PasskeysDeleteProxyHandler(
                        supportPasskeysAndTxmaEnabledConfigurationService(
                                "http://localhost:" + accountDataApiWireMockServer.port()));

        var passkeyId = "def";
        var token = "hij";
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
                        .withHeader("Authorization", WireMock.equalTo("Bearer " + token))
                        .willReturn(aResponse().withStatus(500).withBody(adapiResponse)));

        accountDataApiWireMockServer.stubFor(
                get(urlPathMatching("/accounts/" + publicSubjectId + "/authenticators/passkeys"))
                        .willReturn(aResponse().withStatus(200).withBody(passkeyRetrieveResponse)));

        // Act
        var response =
                makeRequest(
                        Optional.empty(),
                        Map.of("X-ADAPI-AccessToken", token),
                        Collections.emptyMap(),
                        Map.of("publicSubjectId", publicSubjectId, "passkeyIdentifier", passkeyId),
                        Map.ofEntries(Map.entry("clientId", TEST_CLIENT_ID)),
                        Optional.of("delete"));

        // Assert
        assertThat(response, hasStatus(500));
        assertThat(response.getBody(), equalTo(adapiResponse));
        accountDataApiWireMockServer.verify(
                1,
                deleteRequestedFor(
                                urlPathMatching(
                                        "/accounts/"
                                                + publicSubjectId
                                                + "/authenticators/passkeys/"
                                                + passkeyId))
                        .withHeader("Authorization", WireMock.equalTo("Bearer " + token)));
    }

    @Test
    void shouldNotDeletePasskeyIfPasskeysRetrievalFails() {
        // Arrange
        var publicSubjectId = userStore.signUp(TEST_EMAIL, TEST_PASSWORD);
        userStore.addSalt(TEST_EMAIL);
        handler =
                new PasskeysDeleteProxyHandler(
                        supportPasskeysAndTxmaEnabledConfigurationService(
                                "http://localhost:" + accountDataApiWireMockServer.port()));

        var passkeyId = "def";
        var token = "hij";

        accountDataApiWireMockServer.stubFor(
                get(urlPathMatching("/accounts/" + publicSubjectId + "/authenticators/passkeys"))
                        .willReturn(aResponse().withStatus(500)));

        // Act
        var response =
                makeRequest(
                        Optional.empty(),
                        Map.of("X-ADAPI-AccessToken", token),
                        Collections.emptyMap(),
                        Map.of("publicSubjectId", publicSubjectId, "passkeyIdentifier", passkeyId),
                        Map.ofEntries(Map.entry("clientId", TEST_CLIENT_ID)),
                        Optional.of("delete"));

        // Assert
        assertThat(response, hasStatus(500));
        accountDataApiWireMockServer.verify(
                0,
                deleteRequestedFor(
                                urlPathMatching(
                                        "/accounts/"
                                                + publicSubjectId
                                                + "/authenticators/passkeys/"
                                                + passkeyId))
                        .withHeader("Authorization", WireMock.equalTo("Bearer " + token)));
    }
}
