package uk.gov.di.authentication.api;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.github.tomakehurst.wiremock.matching.ContainsPattern;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.RegisterExtension;
import software.amazon.awssdk.services.kms.model.KeyUsageType;
import uk.gov.di.authentication.frontendapi.entity.MfaResetRequest;
import uk.gov.di.authentication.frontendapi.lambda.MfaResetAuthorizeHandler;
import uk.gov.di.authentication.shared.entity.ClientSession;
import uk.gov.di.authentication.shared.entity.ServiceType;
import uk.gov.di.authentication.shared.entity.VectorOfTrust;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.helpers.SaltHelper;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.SerializationService;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;
import uk.gov.di.authentication.sharedtest.extensions.IDReverificationStateExtension;
import uk.gov.di.authentication.sharedtest.extensions.KmsKeyExtension;
import uk.gov.di.authentication.sharedtest.extensions.RedisExtension;
import uk.org.webcompere.systemstubs.environment.EnvironmentVariables;
import uk.org.webcompere.systemstubs.jupiter.SystemStub;
import uk.org.webcompere.systemstubs.jupiter.SystemStubsExtension;

import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.any;
import static com.github.tomakehurst.wiremock.client.WireMock.containing;
import static com.github.tomakehurst.wiremock.client.WireMock.matchingJsonPath;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathMatching;
import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

@ExtendWith(SystemStubsExtension.class)
class MfaResetAuthorizeHandlerIntegrationTest extends ApiGatewayHandlerIntegrationTest {
    private static final String USER_EMAIL = "test@email.com";
    private static final String USER_PASSWORD = "Password123!";
    private static final String USER_PHONE_NUMBER = "+447712345432";
    private static KeyPair keyPair;
    private String sessionId;
    public static final String CLIENT_SESSION_ID = "a-client-session-id";
    private static final ClientID CLIENT_ID = new ClientID("test-client");
    private static final String CLIENT_NAME = "some-client-name";

    private static WireMockServer wireMockServer;

    @SystemStub static EnvironmentVariables environment = new EnvironmentVariables();

    @RegisterExtension
    private static final KmsKeyExtension mfaResetStorageTokenSigningKey =
            new KmsKeyExtension("mfa-reset-storage-token-signing-key", KeyUsageType.SIGN_VERIFY);

    @RegisterExtension
    private static final KmsKeyExtension ipvReverificationRequestsSigningKey =
            new KmsKeyExtension("mfa-reset-jar-signing-key", KeyUsageType.SIGN_VERIFY);

    @RegisterExtension
    public static final RedisExtension redisExtension =
            new RedisExtension(new SerializationService(), new ConfigurationService());

    @RegisterExtension
    private static final IDReverificationStateExtension idReverificationStateExtension =
            new IDReverificationStateExtension();

    @BeforeAll
    static void setupEnvironment() {
        environment.set("TXMA_AUDIT_QUEUE_URL", txmaAuditQueue.getQueueUrl());
        environment.set("IPV_AUTHORISATION_CLIENT_ID", "test-client-id");
        environment.set(
                "MFA_RESET_STORAGE_TOKEN_SIGNING_KEY_ALIAS",
                mfaResetStorageTokenSigningKey.getKeyId());
        environment.set(
                "IPV_REVERIFICATION_REQUESTS_SIGNING_KEY_ALIAS",
                ipvReverificationRequestsSigningKey.getKeyId());

        createTestIPVEncryptionKeyPair();
        putIPVPublicKeyInEnvironmentVariableUntilIPVJWKSAvailable();

        wireMockServer = new WireMockServer(WireMockConfiguration.wireMockConfig().dynamicPort());
        wireMockServer.start();

        wireMockServer.stubFor(
                any(urlPathMatching("/.*"))
                        .willReturn(aResponse().proxiedFrom("http://localhost:45678")));
        environment.set("LOCALSTACK_ENDPOINT", "http://localhost:" + wireMockServer.port());
    }

    @AfterAll
    static void afterAll() {
        if (wireMockServer != null) {
            wireMockServer.stop();
        }
    }

    private static void createTestIPVEncryptionKeyPair() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            fail("Unable to create RSA key pair: " + e.getMessage());
        }
    }

    private static void putIPVPublicKeyInEnvironmentVariableUntilIPVJWKSAvailable() {
        RSAKey rsaKey =
                new RSAKey.Builder((java.security.interfaces.RSAPublicKey) keyPair.getPublic())
                        .privateKey(keyPair.getPrivate())
                        .keyID("key-id")
                        .build();

        try {
            String base64PublicKey =
                    Base64.getEncoder().encodeToString(rsaKey.toRSAPublicKey().getEncoded());

            environment.set(
                    "IPV_PUBLIC_ENCRYPTION_KEY",
                    "-----BEGIN PUBLIC KEY-----\n"
                            + base64PublicKey
                            + "\n-----END PUBLIC KEY-----");
        } catch (JOSEException e) {
            fail("Unable to create IPV public key for test environment: " + e.getMessage());
        }
    }

    @BeforeEach
    void setup() throws Json.JsonException {
        handler = new MfaResetAuthorizeHandler(redisConnectionService);

        var internalCommonSubjectId =
                ClientSubjectHelper.calculatePairwiseIdentifier(
                        new Subject().getValue(),
                        "test.account.gov.uk",
                        SaltHelper.generateNewSalt());

        setUpSession();
        addSessionToSessionStore(internalCommonSubjectId);
        createClientSession();
        registerClient();
        addUserToUserStore();
    }

    private void setUpSession() throws Json.JsonException {
        sessionId = redis.createSession();
    }

    private void addSessionToSessionStore(String internalCommonSubjectId) {
        authSessionStore.addSession(sessionId);
        authSessionStore.addEmailToSession(sessionId, USER_EMAIL);
        authSessionStore.addInternalCommonSubjectIdToSession(sessionId, internalCommonSubjectId);
    }

    private static void createClientSession() throws Json.JsonException {
        var authRequestBuilder =
                new AuthenticationRequest.Builder(
                                ResponseType.CODE,
                                new Scope(OIDCScopeValue.OPENID),
                                new ClientID(CLIENT_ID),
                                URI.create("http://localhost/redirect"))
                        .state(new State())
                        .nonce(new Nonce());

        var clientSession =
                new ClientSession(
                        authRequestBuilder.build().toParameters(),
                        LocalDateTime.now(),
                        VectorOfTrust.getDefaults(),
                        CLIENT_NAME);

        redis.createClientSession(CLIENT_SESSION_ID, clientSession);
    }

    private static void registerClient() {
        clientStore.registerClient(
                CLIENT_ID.getValue(),
                CLIENT_NAME,
                singletonList("redirect-url"),
                singletonList(USER_EMAIL),
                List.of("openid", "email", "phone"),
                "public-key",
                singletonList("http://localhost/post-redirect-logout"),
                "http://example.com",
                String.valueOf(ServiceType.MANDATORY),
                "https://test.com",
                "public");
    }

    private static void addUserToUserStore() {
        String subjectId = "test-subject-id";
        userStore.signUp(USER_EMAIL, USER_PASSWORD, new Subject(subjectId));
        userStore.addVerifiedPhoneNumber(USER_EMAIL, USER_PHONE_NUMBER);
    }

    @Test
    void shouldAuthenticateMfaReset() {
        idReverificationStateExtension.store("orch-redirect-url", "client-session-id");

        wireMockServer.stubFor(
                post(urlEqualTo("/"))
                        .withRequestBody(containing("\"Action\":\"Sign\""))
                        .willReturn(aResponse().proxiedFrom("http://localhost:45678")));

        var response =
                makeRequest(
                        Optional.of(new MfaResetRequest(USER_EMAIL, "")),
                        constructFrontendHeaders(sessionId, CLIENT_SESSION_ID),
                        Map.of());

        assertThat(response, hasStatus(200));

        checkCorrectKeysUsedViaIntegrationWithKms();
        checkTxmaEventPublishedViaIntegrationWithSQS();
    }

    private static void checkCorrectKeysUsedViaIntegrationWithKms() {
        wireMockServer.verify(
                postRequestedFor(urlEqualTo("/"))
                        .withRequestBody(
                                matchingJsonPath(
                                        "$.KeyId",
                                        new ContainsPattern(
                                                ipvReverificationRequestsSigningKey.getKeyId()))));
    }

    private static void checkTxmaEventPublishedViaIntegrationWithSQS() {
        assertEquals(1, txmaAuditQueue.getRawMessages().size());
    }
}
