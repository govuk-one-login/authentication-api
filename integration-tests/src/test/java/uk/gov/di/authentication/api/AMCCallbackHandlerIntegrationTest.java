package uk.gov.di.authentication.api;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.RegisterExtension;
import software.amazon.awssdk.services.kms.model.KeyUsageType;
import uk.gov.di.authentication.frontendapi.entity.amc.AMCCallbackRequest;
import uk.gov.di.authentication.frontendapi.lambda.AMCCallbackHandler;
import uk.gov.di.authentication.shared.helpers.IdGenerator;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;
import uk.gov.di.authentication.sharedtest.extensions.KmsKeyExtension;
import uk.org.webcompere.systemstubs.environment.EnvironmentVariables;
import uk.org.webcompere.systemstubs.jupiter.SystemStub;
import uk.org.webcompere.systemstubs.jupiter.SystemStubsExtension;

import java.net.URI;
import java.util.Map;
import java.util.Optional;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.any;
import static com.github.tomakehurst.wiremock.client.WireMock.configureFor;
import static com.github.tomakehurst.wiremock.client.WireMock.containing;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.matching;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathMatching;
import static org.hamcrest.MatcherAssert.assertThat;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.CLIENT_SESSION_ID;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.DI_PERSISTENT_SESSION_ID;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.IP_ADDRESS;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

@ExtendWith(SystemStubsExtension.class)
class AMCCallbackHandlerIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    private static WireMockServer wireMockServer;
    private String sessionId;
    public static final String ACCESS_TOKEN = "some-access-token";
    public static final String SUCCESSFUL_TOKEN_RESPONSE =
            """
                    {
                        "access_token": "%s",
                        "token_type": "bearer",
                        "expires_in": 3600,
                        "scope": "openid"
                    }
                    """
                    .formatted(ACCESS_TOKEN);
    public static final String JOURNEY_OUTCOME_RESULT =
            """
                            {
                              "outcome_id": "9cd4c45f8f33cced99cfaa48394e1acf5e90f6e2616bba40",
                              "sub": "urn:fdc:gov.uk:2022:JG0RJI1pYbnanbvPs-j4j5-a-PFcmhry9Qu9NCEp5d4",
                              "email": "user@example.com",
                              "scope": "account-delete",
                              "success": true,
                              "journeys": [
                                {
                                  "journey": "account-delete",
                                  "timestamp": 1760718467000,
                                  "success": true,
                                  "details": {}
                                }
                              ]
                            }
                    """;
    public static final String AUTH_CODE = "123456";

    @SystemStub static EnvironmentVariables environment = new EnvironmentVariables();

    @RegisterExtension
    private static final KmsKeyExtension amcJwtSigningKey =
            new KmsKeyExtension("amc-jwt-signing-key", KeyUsageType.SIGN_VERIFY);

    @BeforeAll
    static void setupEnvironment() {
        environment.set("AMC_CLIENT_ID", "a client id");
        environment.set("AUTH_TO_AMC_PRIVATE_AUDIENCE", "auth to amc audience");
        environment.set("AMC_REDIRECT_URI", "https://example.com/redirect");
        environment.set("AUTH_TO_AMC_PRIVATE_SIGNING_KEY", amcJwtSigningKey.getKeyId());
        environment.set(
                "AUTH_TO_ACCOUNT_MANAGEMENT_PRIVATE_SIGNING_KEY", amcJwtSigningKey.getKeyId());
        environment.set("AMC_AUTHORIZE_URI", "https://test-amc.account.gov.uk/authorize");

        wireMockServer = new WireMockServer(WireMockConfiguration.wireMockConfig().dynamicPort());
        wireMockServer.start();
        configureFor("localhost", wireMockServer.port());

        wireMockServer.stubFor(
                any(urlPathMatching("/.*"))
                        .willReturn(aResponse().proxiedFrom("http://localhost:45678")));
        environment.set("LOCALSTACK_ENDPOINT", "http://localhost:" + wireMockServer.port());

        String baseUri = "http://localhost:" + wireMockServer.port();
        URI tokenUri = URI.create(baseUri + "/amc/token");
        environment.set("AMC_TOKEN_URI", tokenUri);
        URI journeyOutcomeUri = URI.create(baseUri + "/amc/journeyoutcome");
        environment.set("AMC_JOURNEY_OUTCOME_URI", journeyOutcomeUri);
    }

    @AfterAll
    static void afterAll() {
        if (wireMockServer != null) {
            wireMockServer.stop();
        }
    }

    @BeforeEach
    void setup() {
        handler = new AMCCallbackHandler();
        sessionId = IdGenerator.generate();
        authSessionStore.addSession(sessionId);
    }

    @Test
    void shouldReturn200AndMakeTokenRequestAndJourneyOutcomeRequestForValidCallback() {
        var tokenResponse =
                aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody(SUCCESSFUL_TOKEN_RESPONSE);
        var journeyOutcomeResponse =
                aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody(JOURNEY_OUTCOME_RESULT);

        stubFor(post(urlPathMatching("/amc/token")).willReturn(tokenResponse));

        stubFor(get(urlPathMatching("/amc/journeyoutcome")).willReturn(journeyOutcomeResponse));

        var requestHeaders =
                constructFrontendHeaders(sessionId, CLIENT_SESSION_ID, DI_PERSISTENT_SESSION_ID);
        requestHeaders.put("X-Forwarded-For", IP_ADDRESS);

        var response =
                makeRequest(
                        Optional.of(new AMCCallbackRequest(AUTH_CODE, "state")),
                        requestHeaders,
                        Map.of());

        var clientAssertionRegex = "eyJ[A-Za-z0-9+/=]+\\.[A-Za-z0-9+/=]+\\.[A-Za-z0-9+/=_-]+";
        WireMock.verify(
                1,
                postRequestedFor(urlPathMatching("/amc/token"))
                        .withHeader("Content-Type", containing("application/x-www-form-urlencoded"))
                        .withHeader("di-persistent-session-id", equalTo(DI_PERSISTENT_SESSION_ID))
                        .withHeader("session-id", equalTo(sessionId))
                        .withHeader("client-session-id", equalTo(CLIENT_SESSION_ID))
                        .withHeader("txma-audit-encoded", equalTo(ENCODED_DEVICE_INFORMATION))
                        .withHeader("x-forwarded-for", equalTo(IP_ADDRESS))
                        .withHeader("user-language", equalTo("en"))
                        .withFormParam("grant_type", equalTo("authorization_code"))
                        .withFormParam("code", equalTo(AUTH_CODE))
                        .withFormParam(
                                "client_assertion_type",
                                equalTo("urn:ietf:params:oauth:client-assertion-type:jwt-bearer"))
                        .withFormParam("client_assertion", matching(clientAssertionRegex)));

        WireMock.verify(
                1,
                getRequestedFor(urlPathMatching("/amc/journeyoutcome"))
                        .withHeader("di-persistent-session-id", equalTo(DI_PERSISTENT_SESSION_ID))
                        .withHeader("session-id", equalTo(sessionId))
                        .withHeader("client-session-id", equalTo(CLIENT_SESSION_ID))
                        .withHeader("txma-audit-encoded", equalTo(ENCODED_DEVICE_INFORMATION))
                        .withHeader("x-forwarded-for", equalTo(IP_ADDRESS))
                        .withHeader("user-language", equalTo("en"))
                        .withHeader(
                                "Authorization", containing("Bearer %s".formatted(ACCESS_TOKEN))));

        assertThat(response, hasStatus(200));
        assertThat(response, hasBody(JOURNEY_OUTCOME_RESULT));
    }
}
