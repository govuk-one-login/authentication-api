package uk.gov.di.authentication.api;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.RegisterExtension;
import software.amazon.awssdk.services.kms.model.KeyUsageType;
import uk.gov.di.authentication.frontendapi.entity.StartPasskeyAssertionRequest;
import uk.gov.di.authentication.frontendapi.lambda.StartPasskeyAssertionHandler;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.helpers.IdGenerator;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;
import uk.gov.di.authentication.sharedtest.extensions.KmsKeyExtension;
import uk.org.webcompere.systemstubs.environment.EnvironmentVariables;
import uk.org.webcompere.systemstubs.jupiter.SystemStub;
import uk.org.webcompere.systemstubs.jupiter.SystemStubsExtension;

import java.util.Map;
import java.util.Optional;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathMatching;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

@ExtendWith(SystemStubsExtension.class)
class StartPasskeyAssertionHandlerIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    private static final String TEST_EMAIL = "user+passkey@digital.cabinet-office.gov.uk";
    private static final String TEST_CREDENTIAL = "credential";
    private static final String FIRST_PASSKEY_ID = "Zmlyc3QtcGFzc2tleS1pZA";
    private static final String SECOND_PASSKEY_ID = "c2Vjb25kLXBhc3NrZXktaWQ";
    private static final String COSE_PUBLIC_KEY_BASE64URL = "cHVibGljLWtleS1jb3Nl";

    private WireMockServer wireMockServer;

    @SystemStub static EnvironmentVariables environment = new EnvironmentVariables();

    @RegisterExtension
    private static final KmsKeyExtension authToAccountDataSigningKey =
            new KmsKeyExtension("auth-to-account-data-signing-key", KeyUsageType.SIGN_VERIFY);

    @BeforeAll
    static void setupEnvironment() {
        environment.set("AUTH_TO_ACCOUNT_DATA_API_AUDIENCE", "https://example.com/ADAPIAudience");
        environment.set("AUTH_ISSUER_CLAIM", "https://signin.account.gov.uk/");
        environment.set("AMC_CLIENT_ID", "amc-client-id");
        environment.set("AUTH_TO_ACCOUNT_DATA_SIGNING_KEY", authToAccountDataSigningKey.getKeyId());
    }

    @BeforeEach
    void setUp() {
        wireMockServer = new WireMockServer(WireMockConfiguration.wireMockConfig().dynamicPort());
        wireMockServer.start();
        txmaAuditQueue.clear();
        handler =
                new StartPasskeyAssertionHandler(
                        supportPasskeysAndTxmaEnabledConfigurationService(
                                "http://localhost:" + wireMockServer.port()));
    }

    @AfterEach
    void tearDown() {
        if (wireMockServer != null) {
            wireMockServer.stop();
        }
    }

    @Nested
    class Success {
        @Test
        void shouldReturnAssertionRequestWithAllowCredentialsWhenUserHasPasskeys() {
            var sessionId = setupUserAndSession();
            var publicSubjectId = userStore.getPublicSubjectIdForEmail(TEST_EMAIL);

            stubPasskeysRetrieveEndpoint(
                    publicSubjectId, 200, passkeysResponse(passkeyJson(FIRST_PASSKEY_ID)));

            var response =
                    makeRequest(
                            Optional.of(new StartPasskeyAssertionRequest()),
                            constructFrontendHeaders(sessionId),
                            Map.of());

            assertThat(response, hasStatus(200));

            var body = JsonParser.parseString(response.getBody()).getAsJsonObject();
            var publicKey = body.getAsJsonObject("publicKey");
            assertNotNull(publicKey.get("challenge"));
            var allowCredentials = publicKey.getAsJsonArray("allowCredentials");
            assertThat(allowCredentials.size(), equalTo(1));
            assertThat(
                    allowCredentials.get(0).getAsJsonObject().get("id").getAsString(),
                    equalTo(FIRST_PASSKEY_ID));
        }

        @Test
        void shouldReturnAllowCredentialsForMultiplePasskeys() {
            var sessionId = setupUserAndSession();
            var publicSubjectId = userStore.getPublicSubjectIdForEmail(TEST_EMAIL);

            stubPasskeysRetrieveEndpoint(
                    publicSubjectId,
                    200,
                    passkeysResponse(
                            passkeyJson(FIRST_PASSKEY_ID), passkeyJson(SECOND_PASSKEY_ID)));

            var response =
                    makeRequest(
                            Optional.of(new StartPasskeyAssertionRequest()),
                            constructFrontendHeaders(sessionId),
                            Map.of());

            assertThat(response, hasStatus(200));
            var body = JsonParser.parseString(response.getBody()).getAsJsonObject();
            var allowCredentials =
                    body.getAsJsonObject("publicKey").getAsJsonArray("allowCredentials");
            assertThat(allowCredentials.size(), equalTo(2));
        }
    }

    @Nested
    class Error {
        @Test
        void shouldReturnAssertionWithNoAllowCredentialsWhenAccountDataApiReturnsError() {
            var sessionId = setupUserAndSession();
            var publicSubjectId = userStore.getPublicSubjectIdForEmail(TEST_EMAIL);

            stubPasskeysRetrieveEndpoint(publicSubjectId, 500, "Internal Server Error");

            var response =
                    makeRequest(
                            Optional.of(new StartPasskeyAssertionRequest()),
                            constructFrontendHeaders(sessionId),
                            Map.of());

            assertThat(response, hasStatus(200));
            var body = JsonParser.parseString(response.getBody()).getAsJsonObject();
            var publicKey = body.getAsJsonObject("publicKey");
            var allowCredentials = publicKey.getAsJsonArray("allowCredentials");
            assertThat(allowCredentials.size(), equalTo(0));
        }

        @Test
        void shouldReturnErrorWhenNoEmailInSession() {
            var sessionId = IdGenerator.generate();
            authSessionStore.addSession(sessionId);

            var response =
                    makeRequest(
                            Optional.of(new StartPasskeyAssertionRequest()),
                            constructFrontendHeaders(sessionId),
                            Map.of());

            assertThat(response, hasStatus(400));
        }

        @Test
        void shouldReturnErrorWhenUserNotFound() {
            var sessionId = IdGenerator.generate();
            authSessionStore.addSession(sessionId);
            authSessionStore.addEmailToSession(sessionId, "nonexistent@example.com");

            var response =
                    makeRequest(
                            Optional.of(new StartPasskeyAssertionRequest()),
                            constructFrontendHeaders(sessionId),
                            Map.of());

            assertThat(response, hasStatus(400));
        }
    }

    private String setupUserAndSession() {
        var sessionId = IdGenerator.generate();
        authSessionStore.addSession(sessionId);
        authSessionStore.addEmailToSession(sessionId, TEST_EMAIL);

        userStore.signUp(TEST_EMAIL, "test-value-7777");
        userStore.addMfaMethod(TEST_EMAIL, MFAMethodType.SMS, false, true, TEST_CREDENTIAL);

        return sessionId;
    }

    private void stubPasskeysRetrieveEndpoint(
            String publicSubjectId, int status, String responseBody) {
        wireMockServer.stubFor(
                get(urlPathMatching("/accounts/" + publicSubjectId + "/authenticators/passkeys"))
                        .willReturn(aResponse().withStatus(status).withBody(responseBody)));
    }

    private static String passkeyJson(String passkeyId) {
        return """
                {
                  "id": "%s",
                  "credential": "%s",
                  "aaguid": "authenticator-1",
                  "isAttested": true,
                  "signCount": 5,
                  "transports": [],
                  "isBackUpEligible": true,
                  "isBackedUp": true,
                  "createdAt": "some-timestamp",
                  "lastUsedAt": "another-timestamp"
                }"""
                .formatted(passkeyId, COSE_PUBLIC_KEY_BASE64URL);
    }

    private static String passkeysResponse(String... passkeys) {
        return """
                {"passkeys": [%s]}"""
                .formatted(String.join(",", passkeys));
    }
}
