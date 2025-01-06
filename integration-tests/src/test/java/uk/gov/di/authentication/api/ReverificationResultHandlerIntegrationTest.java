package uk.gov.di.authentication.api;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.RegisterExtension;
import software.amazon.awssdk.services.kms.model.KeyUsageType;
import uk.gov.di.authentication.frontendapi.entity.ReverificationResultRequest;
import uk.gov.di.authentication.frontendapi.lambda.ReverificationResultHandler;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.helpers.SaltHelper;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;
import uk.gov.di.authentication.sharedtest.extensions.KmsKeyExtension;
import uk.org.webcompere.systemstubs.environment.EnvironmentVariables;
import uk.org.webcompere.systemstubs.jupiter.SystemStub;
import uk.org.webcompere.systemstubs.jupiter.SystemStubsExtension;

import java.net.URI;
import java.util.Map;
import java.util.Optional;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.configureFor;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathMatching;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

@ExtendWith(SystemStubsExtension.class)
class ReverificationResultHandlerIntegrationTest extends ApiGatewayHandlerIntegrationTest {
    private static final String USER_EMAIL = "test@email.com";
    private static final String USER_PASSWORD = "Password123!";
    private static final String USER_PHONE_NUMBER = "+447712345432";

    public static final String SUCCESSFUL_TOKEN_RESPONSE =
            """
            {
                "access_token": "access-token",
                "token_type": "bearer",
                "expires_in": 3600,
                "scope": "openid"
            }
            """;

    private static final String SUCCESSFUL_USER_INFO_HTTP_RESPONSE_CONTENT =
            """
            {
                "sub": "urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6",
                "success": true"
            }
            """;

    private String sessionId;

    @SystemStub static EnvironmentVariables environment = new EnvironmentVariables();

    @RegisterExtension
    private static final KmsKeyExtension mfaResetJarSigningKey =
            new KmsKeyExtension("mfa-reset-jar-signing-key", KeyUsageType.SIGN_VERIFY);

    @BeforeAll
    static void setupEnvironment() {
        environment.set("MFA_RESET_JAR_SIGNING_KEY_ALIAS", mfaResetJarSigningKey.getKeyId());
        environment.set("IPV_AUTHORISATION_CLIENT_ID", "test-client-id");
        environment.set("IPV_AUDIENCE", "test-audience");
        environment.set("TXMA_AUDIT_QUEUE_URL", txmaAuditQueue.getQueueUrl());

        WireMockServer wireMockServer =
                new WireMockServer(WireMockConfiguration.wireMockConfig().dynamicPort());
        wireMockServer.start();
        configureFor("localhost", wireMockServer.port());
        URI ipvUri = URI.create("http://localhost:" + wireMockServer.port());

        environment.set("IPV_BACKEND_URI", ipvUri);
    }

    @BeforeEach
    void setup() throws Json.JsonException {
        handler = new ReverificationResultHandler();
        sessionId = redis.createAuthenticatedSessionWithEmail(USER_EMAIL);
        var internalCommonSubjectId =
                ClientSubjectHelper.calculatePairwiseIdentifier(
                        new Subject().getValue(),
                        "test.account.gov.uk",
                        SaltHelper.generateNewSalt());
        redis.addInternalCommonSubjectIdToSession(sessionId, internalCommonSubjectId);

        String subjectId = "test-subject-id";
        userStore.signUp(USER_EMAIL, USER_PASSWORD, new Subject(subjectId));
        userStore.addVerifiedPhoneNumber(USER_EMAIL, USER_PHONE_NUMBER);
    }

    @Test
    void shouldSuccessfullyProcessAReverificationResult() {
        stubFor(
                post(urlPathMatching("/token"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(SUCCESSFUL_TOKEN_RESPONSE)));

        stubFor(
                get(urlPathMatching("/reverification"))
                        .willReturn(
                                aResponse()
                                        .withStatus(200)
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(SUCCESSFUL_USER_INFO_HTTP_RESPONSE_CONTENT)));

        var response =
                makeRequest(
                        Optional.of(new ReverificationResultRequest("code", "eamil")),
                        constructFrontendHeaders(sessionId, sessionId),
                        Map.of());

        assertThat(response, hasStatus(200));
        checkIntegrationWithTxmaViaSQS();
        checkCorrectKeyUsedToSignRequestToIPVViaIntegrationWithKms();
        checkIntegrationWithIPV();
    }

    private static void checkIntegrationWithTxmaViaSQS() {
        assertEquals(2, txmaAuditQueue.getRawMessages().size());
    }

    private static void checkCorrectKeyUsedToSignRequestToIPVViaIntegrationWithKms() {
        var kmsAccessInterceptor = ConfigurationService.getKmsAccessInterceptor();
        assertTrue(kmsAccessInterceptor.wasKeyUsedToSign(mfaResetJarSigningKey.getKeyId()));
    }

    private static void checkIntegrationWithIPV() {
        WireMock.verify(1, postRequestedFor(urlPathMatching("/token")));
        WireMock.verify(1, getRequestedFor(urlPathMatching("/reverification")));
    }
}
