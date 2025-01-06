package uk.gov.di.authentication.api;

import com.google.common.base.Splitter;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.awaitility.Awaitility;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.RegisterExtension;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.GetPublicKeyRequest;
import software.amazon.awssdk.services.kms.model.GetPublicKeyResponse;
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

import java.net.URI;
import java.time.Duration;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.authentication.frontendapi.services.IPVReverificationService.STATE_STORAGE_PREFIX;
import static uk.gov.di.authentication.shared.domain.CloudwatchMetrics.MFA_RESET_HANDOFF;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

@ExtendWith(SystemStubsExtension.class)
class MfaResetAuthorizeHandlerIntegrationTest extends ApiGatewayHandlerIntegrationTest {
    private static final Logger LOG =
            LogManager.getLogger(MfaResetAuthorizeHandlerIntegrationTest.class);

    private static final String USER_EMAIL = "test@email.com";
    private static final String USER_PASSWORD = "Password123!";
    private static final String USER_PHONE_NUMBER = "+447712345432";
    private String sessionId;

    @SystemStub static EnvironmentVariables environment = new EnvironmentVariables();

    @RegisterExtension
    private static final KmsKeyExtension mfaResetStorageTokenSigningKey =
            new KmsKeyExtension("mfa-reset-storage-token-signing-key", KeyUsageType.SIGN_VERIFY);

    @RegisterExtension
    private static final KmsKeyExtension mfaResetJarSigningKey =
            new KmsKeyExtension("mfa-reset-jar-signing-key", KeyUsageType.SIGN_VERIFY);

    @RegisterExtension
    private static final KmsKeyExtension ipvPublicEncryptionKey =
            new KmsKeyExtension("ipv-authorization-public-key", KeyUsageType.ENCRYPT_DECRYPT);

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

        temporarilyGetTheIPVPublicSigningKeyFromEnvironmentRatherThanIPVJWKSEndPoint();
    }

    private static void
            temporarilyGetTheIPVPublicSigningKeyFromEnvironmentRatherThanIPVJWKSEndPoint() {
        try (KmsClient kmsClient = getKmsClient()) {
            GetPublicKeyRequest getPublicKeyRequest =
                    GetPublicKeyRequest.builder().keyId(ipvPublicEncryptionKey.getKeyId()).build();

            GetPublicKeyResponse getPublicKeyResponse = kmsClient.getPublicKey(getPublicKeyRequest);

            String publicKeyContent =
                    Base64.getEncoder()
                            .encodeToString(getPublicKeyResponse.publicKey().asByteArray());

            StringBuilder publicKeyFormatted = new StringBuilder();
            publicKeyFormatted.append("-----BEGIN PUBLIC KEY-----\n");
            for (final String row : Splitter.fixedLength(64).split(publicKeyContent)) {
                publicKeyFormatted.append(row).append(System.lineSeparator());
            }
            publicKeyFormatted.append("-----END PUBLIC KEY-----\n");

            environment.set("IPV_AUTHORIZATION_PUBLIC_KEY", publicKeyFormatted);
        } catch (Exception e) {
            LOG.error(e.getMessage(), e);
        }
    }

    private static KmsClient getKmsClient() {
        return KmsClient.builder()
                .endpointOverride(URI.create("http://localhost:45678"))
                .credentialsProvider(
                        StaticCredentialsProvider.create(
                                AwsBasicCredentials.create("dummy", "dummy")))
                .region(Region.EU_WEST_2)
                .build();
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
        assertEquals(1, txmaAuditQueue.getRawMessages().size());

        checkCorrectKeysUsedViaIntegrationWithKms();
        checkStateIsStoredViaIntegrationWithRedis(sessionId);
        checkTxmaEventPublishedViaIntegrationWithSQS();
        checkExecutionMetricsPublishedViaIntegrationWithCloudWatch();
    }

    private static void checkCorrectKeysUsedViaIntegrationWithKms() {
        var kmsAccessInterceptor = ConfigurationService.getKmsAccessInterceptor();
        assertTrue(kmsAccessInterceptor.wasKeyUsedToSign(mfaResetJarSigningKey.getKeyId()));
        assertTrue(
                kmsAccessInterceptor.wasKeyUsedToSign(mfaResetStorageTokenSigningKey.getKeyId()));
    }

    private static void checkStateIsStoredViaIntegrationWithRedis(String sessionId) {
        var state = redisExtension.getFromRedis(STATE_STORAGE_PREFIX + sessionId);
        assertNotNull(state);
    }

    private static void checkTxmaEventPublishedViaIntegrationWithSQS() {
        Awaitility.await()
                .atMost(Duration.ofSeconds(60))
                .pollInterval(Duration.ofSeconds(1))
                .until(() -> txmaAuditQueue.getApproximateMessageCount() > 0);
    }

    private static void checkExecutionMetricsPublishedViaIntegrationWithCloudWatch() {
        assertTrue(cloudwatchExtension.hasLoggedMetric(MFA_RESET_HANDOFF.getValue()));
    }
}
