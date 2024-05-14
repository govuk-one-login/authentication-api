package uk.gov.di.orchestration.sharedtest.basetest;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import org.junit.jupiter.api.extension.RegisterExtension;
import software.amazon.awssdk.services.kms.model.KeyUsageType;
import uk.gov.di.orchestration.shared.serialization.Json;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.SerializationService;
import uk.gov.di.orchestration.shared.services.SystemService;
import uk.gov.di.orchestration.sharedtest.extensions.*;

import java.net.HttpCookie;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

public class IntegrationTest {
    private static final String REDIS_HOST = "localhost";
    private static final int REDIS_PORT = 6379;
    private static final String REDIS_PASSWORD = null;
    private static final boolean DOES_REDIS_USE_TLS = false;
    private static final String BEARER_TOKEN = "notify-test-@bearer-token";

    private static final String TXMA_ENCODED_HEADER_VALUE = "dGVzdAo=";
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
    public static final ECKey EC_KEY_PAIR;
    public static final String EC_PUBLIC_KEY;

    static {
        try {
            EC_KEY_PAIR = new ECKeyGenerator(Curve.P_256).generate();
            X509EncodedKeySpec x509EncodedKeySpec =
                    new X509EncodedKeySpec(EC_KEY_PAIR.toPublicKey().getEncoded());
            byte[] x509EncodedPublicKey = x509EncodedKeySpec.getEncoded();
            EC_PUBLIC_KEY = Base64.getEncoder().encodeToString(x509EncodedPublicKey);
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }
    }

    @RegisterExtension
    protected static final SqsQueueExtension notificationsQueue =
            new SqsQueueExtension("notification-queue");

    @RegisterExtension
    protected static final SqsQueueExtension spotQueue = new SqsQueueExtension("spot-queue");

    @RegisterExtension
    protected static final SqsQueueExtension txmaAuditQueue =
            new SqsQueueExtension("txma-audit-queue");

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
    protected static final TokenSigningExtension externalTokenSigner = new TokenSigningExtension();

    @RegisterExtension
    protected static final TokenSigningExtension storageTokenSigner = new TokenSigningExtension();

    @RegisterExtension
    protected static final TokenSigningExtension ipvPrivateKeyJwtSigner =
            new TokenSigningExtension("ipv-token-auth-key");

    @RegisterExtension
    protected static final TokenSigningExtension docAppPrivateKeyJwtSigner =
            new TokenSigningExtension("doc-app-token-auth-key");

    @RegisterExtension
    protected static final TokenSigningExtension orchestrationPrivateKeyJwtSigner =
            new TokenSigningExtension("orchestration-token-auth-key");

    @RegisterExtension
    protected static final KmsKeyExtension authenticationEncryptionKey =
            new KmsKeyExtension("authentication-encryption-key", KeyUsageType.ENCRYPT_DECRYPT);

    @RegisterExtension
    protected static final ParameterStoreExtension configurationParameters =
            new ParameterStoreExtension(
                    Map.ofEntries(
                            Map.entry("local-session-redis-master-host", REDIS_HOST),
                            Map.entry(
                                    "local-session-redis-password", String.valueOf(REDIS_PASSWORD)),
                            Map.entry("local-session-redis-port", String.valueOf(REDIS_PORT)),
                            Map.entry(
                                    "local-session-redis-tls", String.valueOf(DOES_REDIS_USE_TLS)),
                            Map.entry("local-account-management-redis-master-host", REDIS_HOST),
                            Map.entry(
                                    "local-account-management-redis-password",
                                    String.valueOf(REDIS_PASSWORD)),
                            Map.entry(
                                    "local-account-management-redis-port",
                                    String.valueOf(REDIS_PORT)),
                            Map.entry(
                                    "local-account-management-redis-tls",
                                    String.valueOf(DOES_REDIS_USE_TLS)),
                            Map.entry("local-password-pepper", "pepper"),
                            Map.entry("local-auth-public-signing-key", EC_PUBLIC_KEY),
                            Map.entry("local-notify-callback-bearer-token", BEARER_TOKEN)));

    protected static final ConfigurationService TEST_CONFIGURATION_SERVICE =
            new IntegrationTestConfigurationService(
                    externalTokenSigner,
                    storageTokenSigner,
                    ipvPrivateKeyJwtSigner,
                    spotQueue,
                    docAppPrivateKeyJwtSigner,
                    configurationParameters);

    protected static final ConfigurationService TXMA_ENABLED_CONFIGURATION_SERVICE =
            new IntegrationTestConfigurationService(
                    externalTokenSigner,
                    storageTokenSigner,
                    ipvPrivateKeyJwtSigner,
                    spotQueue,
                    docAppPrivateKeyJwtSigner,
                    configurationParameters) {

                @Override
                public String getTxmaAuditQueueUrl() {
                    return txmaAuditQueue.getQueueUrl();
                }
            };

    protected static final ConfigurationService TXMA_AND_AIS_ENABLED_CONFIGURATION_SERVICE =
            new IntegrationTestConfigurationService(
                    externalTokenSigner,
                    storageTokenSigner,
                    ipvPrivateKeyJwtSigner,
                    spotQueue,
                    docAppPrivateKeyJwtSigner,
                    configurationParameters) {

                @Override
                public String getTxmaAuditQueueUrl() {
                    return txmaAuditQueue.getQueueUrl();
                }

                @Override
                public URI getAccountInterventionServiceURI() {
                    try {
                        return new URI("http://ais-uri-example.com/somepath/");
                    } catch (URISyntaxException e) {
                        throw new RuntimeException(e);
                    }
                }
            };

    protected final Json objectMapper = SerializationService.getInstance();

    @RegisterExtension
    protected static final RedisExtension redis =
            new RedisExtension(SerializationService.getInstance(), TEST_CONFIGURATION_SERVICE);

    @RegisterExtension
    protected static final UserStoreExtension userStore = new UserStoreExtension();

    @RegisterExtension
    protected static final ClientStoreExtension clientStore = new ClientStoreExtension();

    @RegisterExtension
    protected static final IdentityStoreExtension identityStore = new IdentityStoreExtension(180);

    @RegisterExtension
    protected static final DocumentAppCredentialStoreExtension documentAppCredentialStore =
            new DocumentAppCredentialStoreExtension(180);

    protected Map<String, String> constructHeaders(Optional<HttpCookie> cookie) {
        final Map<String, String> headers = new HashMap<>();
        cookie.ifPresent(c -> headers.put("Cookie", c.toString()));
        headers.put("txma-audit-encoded", TXMA_ENCODED_HEADER_VALUE);
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

        private final TokenSigningExtension externalTokenSigningKey;
        private final TokenSigningExtension storageTokenSigningKey;
        private final TokenSigningExtension ipvPrivateKeyJwtSigner;
        private final SqsQueueExtension spotQueue;
        private final TokenSigningExtension docAppPrivateKeyJwtSigner;

        public IntegrationTestConfigurationService(
                TokenSigningExtension externalTokenSigningKey,
                TokenSigningExtension storageTokenSigningKey,
                TokenSigningExtension ipvPrivateKeyJwtSigner,
                SqsQueueExtension spotQueue,
                TokenSigningExtension docAppPrivateKeyJwtSigner,
                ParameterStoreExtension parameterStoreExtension) {
            super(parameterStoreExtension.getClient());
            this.externalTokenSigningKey = externalTokenSigningKey;
            this.storageTokenSigningKey = storageTokenSigningKey;
            this.ipvPrivateKeyJwtSigner = ipvPrivateKeyJwtSigner;
            this.spotQueue = spotQueue;
            this.docAppPrivateKeyJwtSigner = docAppPrivateKeyJwtSigner;
        }

        public IntegrationTestConfigurationService(
                TokenSigningExtension externalTokenSigningKey,
                TokenSigningExtension storageTokenSigningKey,
                TokenSigningExtension ipvPrivateKeyJwtSigner,
                SqsQueueExtension spotQueue,
                TokenSigningExtension docAppPrivateKeyJwtSigner,
                ParameterStoreExtension parameterStoreExtension,
                SystemService systemService) {
            super(parameterStoreExtension.getClient());
            this.externalTokenSigningKey = externalTokenSigningKey;
            this.storageTokenSigningKey = storageTokenSigningKey;
            this.ipvPrivateKeyJwtSigner = ipvPrivateKeyJwtSigner;
            this.spotQueue = spotQueue;
            this.docAppPrivateKeyJwtSigner = docAppPrivateKeyJwtSigner;
            super.systemService = systemService;
        }

        @Override
        public String getExternalTokenSigningKeyAlias() {
            return externalTokenSigningKey.getKeyAlias();
        }

        @Override
        public String getStorageTokenSigningKeyAlias() {
            return storageTokenSigningKey.getKeyAlias();
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
        public URI getFrontendBaseURL() {
            return URI.create("http://localhost:3000/");
        }

        @Override
        public URI getSpotQueueURI() {
            return URI.create(spotQueue.getQueueUrl());
        }

        @Override
        public Optional<String> getIPVCapacity() {
            return Optional.of("1");
        }
    }
}
