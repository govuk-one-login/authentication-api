package uk.gov.di.authentication.api;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.RegisterExtension;
import software.amazon.awssdk.services.kms.model.KeyUsageType;
import uk.gov.di.authentication.frontendapi.entity.MfaResetRequest;
import uk.gov.di.authentication.frontendapi.lambda.MfaResetAuthorizeHandler;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.helpers.SaltHelper;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.SerializationService;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;
import uk.gov.di.authentication.sharedtest.doubles.MetricsLoggerTestDouble;
import uk.gov.di.authentication.sharedtest.extensions.CloudWatchExtension;
import uk.gov.di.authentication.sharedtest.extensions.KmsKeyExtension;
import uk.gov.di.authentication.sharedtest.extensions.RedisExtension;
import uk.org.webcompere.systemstubs.environment.EnvironmentVariables;
import uk.org.webcompere.systemstubs.jupiter.SystemStub;
import uk.org.webcompere.systemstubs.jupiter.SystemStubsExtension;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static uk.gov.di.authentication.frontendapi.services.IPVReverificationService.STATE_STORAGE_PREFIX;
import static uk.gov.di.authentication.shared.domain.CloudwatchMetrics.MFA_RESET_HANDOFF;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

@ExtendWith(SystemStubsExtension.class)
class MfaResetAuthorizeHandlerIntegrationTest extends ApiGatewayHandlerIntegrationTest {
    private static final String USER_EMAIL = "test@email.com";
    private static final String USER_PASSWORD = "Password123!";
    private static final String USER_PHONE_NUMBER = "+447712345432";
    private static KeyPair keyPair;
    private String sessionId;

    @SystemStub static EnvironmentVariables environment = new EnvironmentVariables();

    @RegisterExtension
    private static final KmsKeyExtension mfaResetStorageTokenSigningKey =
            new KmsKeyExtension("mfa-reset-storage-token-signing-key", KeyUsageType.SIGN_VERIFY);

    @RegisterExtension
    private static final KmsKeyExtension mfaResetJarSigningKey =
            new KmsKeyExtension("mfa-reset-jar-signing-key", KeyUsageType.SIGN_VERIFY);

    @RegisterExtension
    public static final RedisExtension redisExtension =
            new RedisExtension(new SerializationService(), new ConfigurationService());

    @RegisterExtension
    private static final CloudWatchExtension cloudwatchExtension = new CloudWatchExtension();

    @BeforeAll
    static void setupEnvironment() {
        environment.set("TXMA_AUDIT_QUEUE_URL", txmaAuditQueue.getQueueUrl());
        environment.set("IPV_AUTHORISATION_CLIENT_ID", "test-client-id");
        environment.set(
                "MFA_RESET_STORAGE_TOKEN_SIGNING_KEY_ALIAS",
                mfaResetStorageTokenSigningKey.getKeyId());
        environment.set("MFA_RESET_JAR_SIGNING_KEY_ID", mfaResetJarSigningKey.getKeyId());

        createTestIPVEncryptionKeyPair();
        putIPVPublicKeyInEnvironmentVariableUntilIPVJWKSAvailable();
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
                    "IPV_AUTHORIZATION_PUBLIC_KEY",
                    "-----BEGIN PUBLIC KEY-----\n"
                            + base64PublicKey
                            + "\n-----END PUBLIC KEY-----");
        } catch (JOSEException e) {
            fail("Unable to create IPV public key for test environment: " + e.getMessage());
        }
    }

    @BeforeEach
    void setup() throws Json.JsonException {
        ConfigurationService configurationService = ConfigurationService.getInstance();
        configurationService.setMetricsLoggerAdapter(
                new MetricsLoggerTestDouble(
                        cloudwatchExtension.getLogGroupName(),
                        cloudwatchExtension.getLogStreamName()));

        handler = new MfaResetAuthorizeHandler();

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
    void shouldAuthenticateMfaReset() {
        var response =
                makeRequest(
                        Optional.of(new MfaResetRequest(USER_EMAIL)),
                        constructFrontendHeaders(sessionId, sessionId),
                        Map.of());

        assertThat(response, hasStatus(200));

        checkCorrectKeysUsedViaIntegrationWithKms(response.getBody());
        checkStateIsStoredViaIntegrationWithRedis(sessionId);
        checkTxmaEventPublishedViaIntegrationWithSQS();
        checkExecutionMetricsPublishedViaIntegrationWithCloudWatch();
    }

    private static void checkCorrectKeysUsedViaIntegrationWithKms(String body) {
        var kmsAccessInterceptor = ConfigurationService.getKmsAccessInterceptor();
        assertTrue(kmsAccessInterceptor.wasKeyUsedToSign(mfaResetJarSigningKey.getKeyId()));
        assertTrue(
                kmsAccessInterceptor.wasKeyUsedToSign(mfaResetStorageTokenSigningKey.getKeyId()));
        ObjectMapper objectMapper = new ObjectMapper();
        try {
            JsonNode rootNode = objectMapper.readTree(body);
            String url = rootNode.get("authorize_url").asText();
            Map<String, String> params =
                    Arrays.stream(url.substring(1).split("&"))
                            .map(param -> param.split("="))
                            .collect(Collectors.toMap(param -> param[0], param -> param[1]));

            String request = params.get("request");

            JWEObject jweObject = JWEObject.parse(request);
            jweObject.decrypt(new RSADecrypter(keyPair.getPrivate()));

            var payload = jweObject.getPayload().toString();

            SignedJWT signedJWT = SignedJWT.parse(payload);

            assertNotNull(signedJWT);
        } catch (JsonProcessingException e) {
            fail("Body could not be parsed: " + body);
        } catch (ParseException | JOSEException e) {
            fail("JOSE exception processing JAR", e);
        }
    }

    private static void checkStateIsStoredViaIntegrationWithRedis(String sessionId) {
        var state = redisExtension.getFromRedis(STATE_STORAGE_PREFIX + sessionId);
        assertNotNull(state);
    }

    private static void checkTxmaEventPublishedViaIntegrationWithSQS() {
        assertEquals(1, txmaAuditQueue.getRawMessages().size());
    }

    private static void checkExecutionMetricsPublishedViaIntegrationWithCloudWatch() {
        assertTrue(cloudwatchExtension.hasLoggedMetric(MFA_RESET_HANDOFF.getValue()));
    }
}
