package uk.gov.di.accountmanagement.api;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import uk.gov.di.accountmanagement.lambda.AccountDeleteProxyHandler;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
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
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static java.lang.String.format;
import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static uk.gov.di.authentication.sharedtest.helper.AuditAssertionsHelper.assertNoTxmaAuditEventsReceived;
import static uk.gov.di.authentication.sharedtest.helper.AuditAssertionsHelper.assertTxmaAuditEventsReceived;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

@ExtendWith(SystemStubsExtension.class)
class AccountDeleteProxyHandlerIntegrationTest extends ApiGatewayHandlerIntegrationTest {
    private WireMockServer accountDataApiWireMockServer;

    private static final String AUTHORIZATION_HEADER_FIELD = "Authorization";
    private static final String ADAPI_TOKEN_HEADER = "X-ADAPI-AccessToken";
    private static final String TEST_EMAIL = "joe.bloggs@digital.cabinet-office.gov.uk";
    private static final String TEST_PASSWORD = "password";
    private static final String TEST_PHONE_NUMBER = "+447700900000";
    private static final Subject SUBJECT = new Subject();
    private static final String INTERNAL_SECTOR_URI = "https://test.account.gov.uk";
    private static final String INTERNAL_SECTOR_HOST = "test.account.gov.uk";
    private static final String TOKEN = "def";

    private static final String SESSION_ID = "session-id";
    private static final String CLIENT_SESSION_ID = "Y2xpZW50LXNlc3Npb24taWQ=";
    private static final String PERSISTENT_SESSION_ID = "cGVyc2lzdGVudC1zZXNzaW9uLWlk";
    private static final String IP_ADDRESS = "123.123.123.123";
    private static final String ENCODED_DEVICE_INFORMATION = "device-information";

    private static final String REQUEST_BODY =
            """
            {
              "clientId": "amc",
              "reason": "USER_INITIATED"
            }
            """;

    private String publicSubjectId;
    private String expectedUserId;

    @SystemStub static EnvironmentVariables environment = new EnvironmentVariables();

    @BeforeEach
    void setup() {
        accountDataApiWireMockServer =
                new WireMockServer(WireMockConfiguration.wireMockConfig().dynamicPort());
        accountDataApiWireMockServer.start();

        environment.set(
                "ACCOUNT_DATA_API_URI", "http://localhost:" + accountDataApiWireMockServer.port());
        environment.set("INTERNAl_SECTOR_URI", INTERNAL_SECTOR_URI);

        publicSubjectId = userStore.signUp(TEST_EMAIL, TEST_PASSWORD, SUBJECT);
        userStore.addVerifiedPhoneNumber(TEST_EMAIL, TEST_PHONE_NUMBER);
        var salt = userStore.addSalt(TEST_EMAIL);
        expectedUserId =
                ClientSubjectHelper.calculatePairwiseIdentifier(
                        SUBJECT.getValue(), INTERNAL_SECTOR_HOST, salt);

        handler = new AccountDeleteProxyHandler(TXMA_ENABLED_CONFIGURATION_SERVICE);

        txmaAuditQueue.clear();
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
        assertTxmaAuditEventsReceived(txmaAuditQueue, List.of("AUTH_DELETE_ACCOUNT"));
    }

    @Test
    void shouldEmitAuditEventWithExpectedUserRestrictedAndExtensionsWhenAccountDeleted() {
        stubAccountDataApiDelete(204, "");

        makeAccountDeleteRequest();

        var rawEvents =
                assertTxmaAuditEventsReceived(txmaAuditQueue, List.of("AUTH_DELETE_ACCOUNT"));
        var event = rawEvents.get(0);

        var expectedUser =
                format(
                        """
                        {
                          "email": "%s",
                          "govuk_signin_journey_id": "%s",
                          "ip_address": "%s",
                          "persistent_session_id": "%s",
                          "public_subject_id": "%s",
                          "session_id": "%s",
                          "user_id": "%s",
                          "phone": "%s"
                        }
                        """,
                        TEST_EMAIL,
                        CLIENT_SESSION_ID,
                        IP_ADDRESS,
                        PERSISTENT_SESSION_ID,
                        publicSubjectId,
                        SESSION_ID,
                        expectedUserId,
                        TEST_PHONE_NUMBER);

        var expectedRestricted =
                format(
                        """
                        {
                          "device_information": {
                            "encoded": "%s"
                          }
                        }
                        """,
                        ENCODED_DEVICE_INFORMATION);

        var expectedExtensions =
                """
                {
                  "account_deletion_reason": "USER_INITIATED",
                  "phone_number_country_code": "44"
                }
                """;

        assertThatJson(event).node("user").isEqualTo(expectedUser);
        assertThatJson(event).node("restricted").isEqualTo(expectedRestricted);
        assertThatJson(event).node("extensions").isEqualTo(expectedExtensions);
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
        assertNoTxmaAuditEventsReceived(txmaAuditQueue);
    }

    private void stubAccountDataApiDelete(int statusCode, String body) {
        accountDataApiWireMockServer.stubFor(
                delete(urlPathEqualTo("/accounts/" + publicSubjectId))
                        .withHeader(AUTHORIZATION_HEADER_FIELD, WireMock.equalTo("Bearer " + TOKEN))
                        .willReturn(aResponse().withStatus(statusCode).withBody(body)));
    }

    private APIGatewayProxyResponseEvent makeAccountDeleteRequest() {
        return makeRequest(
                Optional.of(REQUEST_BODY),
                Map.ofEntries(
                        Map.entry(ADAPI_TOKEN_HEADER, TOKEN),
                        Map.entry("Session-Id", SESSION_ID),
                        Map.entry("Client-Session-Id", CLIENT_SESSION_ID),
                        Map.entry("di-persistent-session-id", PERSISTENT_SESSION_ID),
                        Map.entry("X-Forwarded-For", IP_ADDRESS),
                        Map.entry("txma-audit-encoded", ENCODED_DEVICE_INFORMATION)),
                Collections.emptyMap(),
                Map.of("publicSubjectId", publicSubjectId));
    }

    private void verifyAccountDataApiDeleteCalledOnce() {
        accountDataApiWireMockServer.verify(
                1,
                deleteRequestedFor(urlPathEqualTo("/accounts/" + publicSubjectId))
                        .withHeader(
                                AUTHORIZATION_HEADER_FIELD, WireMock.equalTo("Bearer " + TOKEN)));
    }
}
