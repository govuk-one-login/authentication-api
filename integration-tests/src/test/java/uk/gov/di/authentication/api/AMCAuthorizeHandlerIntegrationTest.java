package uk.gov.di.authentication.api;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import software.amazon.awssdk.services.kms.model.KeyUsageType;
import uk.gov.di.authentication.frontendapi.entity.amc.AMCJourneyType;
import uk.gov.di.authentication.frontendapi.lambda.AMCAuthorizeHandler;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.helpers.IdGenerator;
import uk.gov.di.authentication.shared.helpers.SaltHelper;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;
import uk.gov.di.authentication.sharedtest.extensions.AMCStateExtension;
import uk.gov.di.authentication.sharedtest.extensions.KmsKeyExtension;
import uk.org.webcompere.systemstubs.environment.EnvironmentVariables;
import uk.org.webcompere.systemstubs.jupiter.SystemStub;
import uk.org.webcompere.systemstubs.jupiter.SystemStubsExtension;

import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathMatching;
import static com.google.gson.JsonParser.parseString;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

@ExtendWith(SystemStubsExtension.class)
class AMCAuthorizeHandlerIntegrationTest extends ApiGatewayHandlerIntegrationTest {
    private static final String USER_EMAIL = "test@email.com";
    private static RSAKey rsaKey;

    private static WireMockServer wireMockServer;
    private String sessionId;
    private static final String CLIENT_SESSION_ID = "a-client-session-id";

    @SystemStub static EnvironmentVariables environment = new EnvironmentVariables();

    @RegisterExtension
    private static final KmsKeyExtension amcJwtSigningKey =
            new KmsKeyExtension("amc-jwt-signing-key", KeyUsageType.SIGN_VERIFY);

    @RegisterExtension
    private static final AMCStateExtension amcStateExtension = new AMCStateExtension();

    @BeforeAll
    static void setupEnvironment() {
        environment.set("AUTH_TO_AMC_TRANSPORT_JWT_SIGNING_KEY", amcJwtSigningKey.getKeyId());
        environment.set("AUTH_TO_ACCOUNT_MANAGEMENT_SIGNING_KEY", amcJwtSigningKey.getKeyId());
        environment.set("AUTH_TO_ACCOUNT_DATA_SIGNING_KEY", amcJwtSigningKey.getKeyId());
        environment.set("AUTH_ISSUER_CLAIM", "https://test.account.gov.uk");
        environment.set("AUTH_TO_AUTH_AUDIENCE", "https://test.account.gov.uk");
        environment.set("AUTH_TO_AMC_PUBLIC_AUDIENCE", "https://manage.account.gov.uk/authorize");
        environment.set("AMC_CLIENT_ID", "test-amc-client");
        environment.set("AMC_AUTHORIZE_URI", "https://test-amc.account.gov.uk/authorize");
        environment.set("AMC_REDIRECT_URI", "https://test.account.gov.uk/amc/callback");

        KeyPair keyPair;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (Exception e) {
            throw new RuntimeException("Unable to create RSA key pair", e);
        }

        rsaKey =
                new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                        .privateKey((RSAPrivateKey) keyPair.getPrivate())
                        .keyID("amc-test-key")
                        .build();

        wireMockServer = new WireMockServer(WireMockConfiguration.wireMockConfig().dynamicPort());
        wireMockServer.start();
        environment.set(
                "AMC_JWKS_URL",
                "http://localhost:" + wireMockServer.port() + "/.well-known/jwks.json");
    }

    @AfterAll
    static void afterAll() {
        if (wireMockServer != null) {
            wireMockServer.stop();
        }
    }

    @BeforeEach
    void setup() {
        sessionId = IdGenerator.generate();
        var internalCommonSubjectId =
                ClientSubjectHelper.calculatePairwiseIdentifier(
                        new Subject().getValue(),
                        "test.account.gov.uk",
                        SaltHelper.generateNewSalt());

        wireMockServer.resetAll();
        wireMockServer.stubFor(
                get(urlPathMatching("/.well-known/jwks.json"))
                        .willReturn(
                                aResponse()
                                        .withHeader("Content-Type", "application/json")
                                        .withBody(
                                                new JWKSet(List.of(rsaKey))
                                                        .toPublicJWKSet()
                                                        .toString())));

        authSessionStore.addSession(sessionId);
        authSessionStore.addEmailToSession(sessionId, USER_EMAIL);
        authSessionStore.addInternalCommonSubjectIdToSession(sessionId, internalCommonSubjectId);
        authSessionStore.addClientIdToSession(sessionId, "test-client");
        authSessionStore.addRpSectorIdentifierHostToSession(sessionId, "test.com");

        userStore.signUp(USER_EMAIL, "password", new Subject("test-subject-id"));
    }

    @ParameterizedTest
    @EnumSource(AMCJourneyType.class)
    void shouldAuthorizeAMCInitiation(AMCJourneyType amcJourneyType) throws Exception {
        handler = new AMCAuthorizeHandler();

        var requestBody =
                """
                {
                    "journeyType": "%s"
                    }
                """
                        .formatted(amcJourneyType);
        var response =
                makeRequest(
                        Optional.of(requestBody),
                        constructFrontendHeaders(sessionId, CLIENT_SESSION_ID),
                        Map.of());

        assertThat(response, hasStatus(200));
        String responseBody = response.getBody();

        var jsonObject = parseString(responseBody).getAsJsonObject();
        // Because we can't directly construct the full json response, here we check that the number
        // of key value pairs in the json is equal to the number of fields we're retrieving in
        // tests, meaning that we're checking the entire json object
        assertEquals(2, jsonObject.size());
        String redirectUrl = jsonObject.get("redirectUrl").getAsString();

        assertTrue(redirectUrl.startsWith("https://test-amc.account.gov.uk/authorize?"));
        assertTrue(redirectUrl.contains("response_type=code"));
        assertTrue(redirectUrl.contains("client_id=test-amc-client"));
        assertTrue(redirectUrl.contains("request="));
        assertTrue(redirectUrl.contains("scope="));
        assertTrue(redirectUrl.contains("redirect_uri="));
        assertTrue(redirectUrl.contains("state="));

        String requestParam =
                Arrays.stream(new URI(redirectUrl).getQuery().split("&"))
                        .filter(p -> p.startsWith("request="))
                        .map(p -> p.substring("request=".length()))
                        .findFirst()
                        .orElseThrow();
        EncryptedJWT encryptedJWT = EncryptedJWT.parse(requestParam);

        assertNotNull(encryptedJWT.getHeader());
        assertEquals(JWEAlgorithm.RSA_OAEP_256, encryptedJWT.getHeader().getAlgorithm());
        assertEquals(EncryptionMethod.A256GCM, encryptedJWT.getHeader().getEncryptionMethod());

        String amcCookie = jsonObject.get("amcCookie").getAsString();
        assertFalse(amcCookie.isEmpty());
        RSADecrypter decrypter = new RSADecrypter(rsaKey.toPrivateKey());
        assertDoesNotThrow(() -> encryptedJWT.decrypt(decrypter));
    }

    @Test
    void shouldReturn400WhenUserProfileDoesNotExist() {
        handler = new AMCAuthorizeHandler();
        String emailWithoutProfile = "no-profile@email.com";
        authSessionStore.addEmailToSession(sessionId, emailWithoutProfile);

        var requestBody =
                """
                {
                    "journeyType": "SFAD"
                    }
                """;

        var response =
                makeRequest(
                        Optional.of(requestBody),
                        constructFrontendHeaders(sessionId, CLIENT_SESSION_ID),
                        Map.of());

        assertThat(response, hasStatus(400));
    }
}
