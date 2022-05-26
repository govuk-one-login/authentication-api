package uk.gov.di.authentication.sharedtest.basetest;

import com.amazonaws.services.kms.model.KeyUsageType;
import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.authentication.shared.helpers.ObjectMapperFactory;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.SerializationService;
import uk.gov.di.authentication.sharedtest.extensions.AuditSnsTopicExtension;
import uk.gov.di.authentication.sharedtest.extensions.ClientStoreExtension;
import uk.gov.di.authentication.sharedtest.extensions.CloudwatchMetricsExtension;
import uk.gov.di.authentication.sharedtest.extensions.DocumentAppCredentialStoreExtension;
import uk.gov.di.authentication.sharedtest.extensions.IdentityStoreExtension;
import uk.gov.di.authentication.sharedtest.extensions.KmsKeyExtension;
import uk.gov.di.authentication.sharedtest.extensions.ParameterStoreExtension;
import uk.gov.di.authentication.sharedtest.extensions.RedisExtension;
import uk.gov.di.authentication.sharedtest.extensions.SnsTopicExtension;
import uk.gov.di.authentication.sharedtest.extensions.SqsQueueExtension;
import uk.gov.di.authentication.sharedtest.extensions.TokenSigningExtension;
import uk.gov.di.authentication.sharedtest.extensions.UserStoreExtension;

import java.net.HttpCookie;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static org.mockito.Mockito.mock;

public abstract class HandlerIntegrationTest<Q, S> {
    protected static final String LOCAL_ENDPOINT_FORMAT =
            "http://localhost:45678/restapis/%s/local/_user_request_";
    protected static final String LOCAL_API_GATEWAY_ID =
            Optional.ofNullable(System.getenv().get("API_GATEWAY_ID")).orElse("");
    protected static final String API_KEY =
            Optional.ofNullable(System.getenv().get("API_KEY")).orElse("");
    protected static final String FRONTEND_API_KEY =
            Optional.ofNullable(System.getenv().get("FRONTEND_API_KEY")).orElse("");
    public static final String ROOT_RESOURCE_URL =
            Optional.ofNullable(System.getenv().get("ROOT_RESOURCE_URL"))
                    .orElse(String.format(LOCAL_ENDPOINT_FORMAT, LOCAL_API_GATEWAY_ID));
    public static final String FRONTEND_ROOT_RESOURCE_URL =
            Optional.ofNullable(System.getenv().get("ROOT_RESOURCE_URL"))
                    .orElse(
                            String.format(
                                    LOCAL_ENDPOINT_FORMAT,
                                    Optional.ofNullable(
                                                    System.getenv().get("FRONTEND_API_GATEWAY_ID"))
                                            .orElse("")));

    @RegisterExtension
    protected static final SqsQueueExtension notificationsQueue =
            new SqsQueueExtension("notification-queue");

    @RegisterExtension
    protected static final SqsQueueExtension spotQueue = new SqsQueueExtension("spot-queue");

    @RegisterExtension
    protected static final AuditSnsTopicExtension auditTopic =
            new AuditSnsTopicExtension("local-events");

    @RegisterExtension
    protected static final KmsKeyExtension auditSigningKey =
            new KmsKeyExtension("audit-signing-key");

    @RegisterExtension
    protected static final KmsKeyExtension ipvEncryptionKey =
            new KmsKeyExtension("ipv-encryption-key", KeyUsageType.ENCRYPT_DECRYPT);

    @RegisterExtension
    protected static final CloudwatchMetricsExtension cloudwatchMetrics =
            new CloudwatchMetricsExtension();

    @RegisterExtension
    protected static final TokenSigningExtension tokenSigner = new TokenSigningExtension();

    @RegisterExtension
    protected static final TokenSigningExtension ipvPrivateKeyJwtSigner =
            new TokenSigningExtension("ipv-token-auth-key");

    @RegisterExtension
    protected static final TokenSigningExtension docAppPrivateKeyJwtSigner =
            new TokenSigningExtension("doc-app-token-auth-key");

    @RegisterExtension
    protected static final ParameterStoreExtension configurationParameters =
            new ParameterStoreExtension(
                    Map.of(
                            "local-session-redis-master-host", "localhost",
                            "local-session-redis-password", "null",
                            "local-session-redis-port", "6379",
                            "local-session-redis-tls", "false",
                            "local-account-management-redis-master-host", "localhost",
                            "local-account-management-redis-password", "null",
                            "local-account-management-redis-port", "6379",
                            "local-account-management-redis-tls", "false",
                            "local-password-pepper", "pepper"));

    protected final ConfigurationService TEST_CONFIGURATION_SERVICE =
            new IntegrationTestConfigurationService(
                    auditTopic,
                    notificationsQueue,
                    auditSigningKey,
                    tokenSigner,
                    ipvPrivateKeyJwtSigner,
                    spotQueue,
                    docAppPrivateKeyJwtSigner);

    protected RequestHandler<Q, S> handler;
    protected final Json objectMapper = SerializationService.getInstance();
    protected final Context context = mock(Context.class);

    @RegisterExtension
    protected static final RedisExtension redis =
            new RedisExtension(ObjectMapperFactory.getInstance());

    @RegisterExtension
    protected static final UserStoreExtension userStore = new UserStoreExtension();

    @RegisterExtension
    protected static final ClientStoreExtension clientStore = new ClientStoreExtension();

    @RegisterExtension
    protected static final IdentityStoreExtension identityStore = new IdentityStoreExtension();

    @RegisterExtension
    protected static final DocumentAppCredentialStoreExtension documentAppCredentialStore =
            new DocumentAppCredentialStoreExtension();

    protected Map<String, String> constructHeaders(Optional<HttpCookie> cookie) {
        final Map<String, String> headers = new HashMap<>();
        cookie.ifPresent(c -> headers.put("Cookie", c.toString()));
        return headers;
    }

    protected Map<String, String> constructFrontendHeaders(String sessionId) {
        return constructFrontendHeaders(sessionId, Optional.empty(), Optional.empty());
    }

    protected Map<String, String> constructFrontendHeaders(
            String sessionId, String clientSessionId) {
        return constructFrontendHeaders(sessionId, Optional.of(clientSessionId), Optional.empty());
    }

    protected Map<String, String> constructFrontendHeaders(
            String sessionId, String clientSessionId, String persistentSessionId) {
        return constructFrontendHeaders(
                sessionId, Optional.ofNullable(clientSessionId), Optional.of(persistentSessionId));
    }

    protected Map<String, String> constructFrontendHeaders(
            String sessionId,
            Optional<String> clientSessionId,
            Optional<String> persistentSessionId) {
        var headers = new HashMap<String, String>();
        headers.put("Session-Id", sessionId);
        headers.put("X-API-Key", FRONTEND_API_KEY);
        clientSessionId.ifPresent(id -> headers.put("Client-Session-Id", id));
        persistentSessionId.ifPresent(id -> headers.put("di-persistent-session-id", id));
        return headers;
    }

    protected HttpCookie buildSessionCookie(String sessionID, String clientSessionID) {
        return new HttpCookie("gs", sessionID + "." + clientSessionID);
    }

    public static class IntegrationTestConfigurationService extends ConfigurationService {

        private final SqsQueueExtension notificationQueue;
        private final KmsKeyExtension auditSigningKey;
        private final TokenSigningExtension tokenSigningKey;
        private final SnsTopicExtension auditEventTopic;
        private final TokenSigningExtension ipvPrivateKeyJwtSigner;
        private final SqsQueueExtension spotQueue;
        private final TokenSigningExtension docAppPrivateKeyJwtSigner;

        public IntegrationTestConfigurationService(
                SnsTopicExtension auditEventTopic,
                SqsQueueExtension notificationQueue,
                KmsKeyExtension auditSigningKey,
                TokenSigningExtension tokenSigningKey,
                TokenSigningExtension ipvPrivateKeyJwtSigner,
                SqsQueueExtension spotQueue,
                TokenSigningExtension docAppPrivateKeyJwtSigner) {
            this.auditEventTopic = auditEventTopic;
            this.notificationQueue = notificationQueue;
            this.tokenSigningKey = tokenSigningKey;
            this.auditSigningKey = auditSigningKey;
            this.ipvPrivateKeyJwtSigner = ipvPrivateKeyJwtSigner;
            this.spotQueue = spotQueue;
            this.docAppPrivateKeyJwtSigner = docAppPrivateKeyJwtSigner;
        }

        @Override
        public String getEmailQueueUri() {
            return notificationQueue.getQueueUrl();
        }

        @Override
        public String getEventsSnsTopicArn() {
            return auditEventTopic.getTopicArn();
        }

        @Override
        public String getAuditSigningKeyAlias() {
            return auditSigningKey.getKeyAlias();
        }

        @Override
        public String getTokenSigningKeyAlias() {
            return tokenSigningKey.getKeyAlias();
        }

        @Override
        public String getIPVTokenSigningKeyAlias() {
            return ipvPrivateKeyJwtSigner.getKeyAlias();
        }

        @Override
        public String getDocAppTokenSigningKeyAlias() {
            return docAppPrivateKeyJwtSigner.getKeyAlias();
        }

        @Override
        public String getFrontendBaseUrl() {
            return "http://localhost:3000/reset-password?code=";
        }

        @Override
        public String getSpotQueueUri() {
            return spotQueue.getQueueUrl();
        }

        @Override
        public Optional<String> getIPVCapacity() {
            return Optional.of("1");
        }
    }
}
