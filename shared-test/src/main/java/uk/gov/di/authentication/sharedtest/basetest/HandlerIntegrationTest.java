package uk.gov.di.authentication.sharedtest.basetest;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.extension.RegisterExtension;
import software.amazon.awssdk.services.kms.model.KeyUsageType;
import uk.gov.di.authentication.shared.entity.ServiceType;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.RedisConnectionService;
import uk.gov.di.authentication.shared.services.SerializationService;
import uk.gov.di.authentication.shared.services.SystemService;
import uk.gov.di.authentication.sharedtest.extensions.AccountModifiersStoreExtension;
import uk.gov.di.authentication.sharedtest.extensions.AuditSnsTopicExtension;
import uk.gov.di.authentication.sharedtest.extensions.ClientStoreExtension;
import uk.gov.di.authentication.sharedtest.extensions.CommonPasswordsExtension;
import uk.gov.di.authentication.sharedtest.extensions.IdentityStoreExtension;
import uk.gov.di.authentication.sharedtest.extensions.KmsKeyExtension;
import uk.gov.di.authentication.sharedtest.extensions.ParameterStoreExtension;
import uk.gov.di.authentication.sharedtest.extensions.RedisExtension;
import uk.gov.di.authentication.sharedtest.extensions.SqsQueueExtension;
import uk.gov.di.authentication.sharedtest.extensions.TokenSigningExtension;
import uk.gov.di.authentication.sharedtest.extensions.UserStoreExtension;
import uk.gov.di.authentication.sharedtest.helper.KeyPairHelper;

import java.net.HttpCookie;
import java.net.URI;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static java.lang.String.valueOf;
import static java.util.Collections.singletonList;
import static java.util.Map.entry;
import static org.mockito.Mockito.mock;
import static uk.gov.di.authentication.shared.lambda.BaseFrontendHandler.TXMA_AUDIT_ENCODED_HEADER;

public abstract class HandlerIntegrationTest<Q, S> {
    private static final String REDIS_HOST = "localhost";
    private static final int REDIS_PORT = 6379;
    private static final String REDIS_PASSWORD = null;
    private static final boolean DOES_REDIS_USE_TLS = false;
    private static final String BEARER_TOKEN = "notify-test-@bearer-token";
    protected static final String FRONTEND_API_KEY =
            Optional.ofNullable(System.getenv().get("FRONTEND_API_KEY")).orElse("");

    public static final ECKey EC_KEY_PAIR;
    public static final String EC_PUBLIC_KEY;
    public static final String ENCODED_DEVICE_INFORMATION =
            "R21vLmd3QilNKHJsaGkvTFxhZDZrKF44SStoLFsieG0oSUY3aEhWRVtOMFRNMVw1dyInKzB8OVV5N09hOi8kLmlLcWJjJGQiK1NPUEJPPHBrYWJHP358NDg2ZDVc";

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

    protected static RedisConnectionService redisConnectionService;

    @BeforeAll
    static void beforeAll() {
        redisConnectionService = new RedisConnectionService(TEST_CONFIGURATION_SERVICE);
    }

    @AfterAll
    static void afterAll() {
        redisConnectionService.close();
    }

    @RegisterExtension
    protected static final SqsQueueExtension notificationsQueue =
            new SqsQueueExtension("notification-queue");

    @RegisterExtension
    protected static final SqsQueueExtension pendingEmailCheckQueue =
            new SqsQueueExtension("pending-email-check-queue");

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
    protected static final TokenSigningExtension tokenSigner = new TokenSigningExtension();

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
                            entry("local-session-redis-master-host", REDIS_HOST),
                            entry("local-session-redis-password", valueOf(REDIS_PASSWORD)),
                            entry("local-session-redis-port", valueOf(REDIS_PORT)),
                            entry("local-session-redis-tls", valueOf(DOES_REDIS_USE_TLS)),
                            entry("local-account-management-redis-master-host", REDIS_HOST),
                            entry(
                                    "local-account-management-redis-password",
                                    valueOf(REDIS_PASSWORD)),
                            entry("local-account-management-redis-port", valueOf(REDIS_PORT)),
                            entry(
                                    "local-account-management-redis-tls",
                                    valueOf(DOES_REDIS_USE_TLS)),
                            entry("local-password-pepper", "pepper"),
                            entry("local-auth-public-signing-key", EC_PUBLIC_KEY),
                            entry("local-notify-callback-bearer-token", BEARER_TOKEN)));

    protected static final ConfigurationService TEST_CONFIGURATION_SERVICE =
            new IntegrationTestConfigurationService(
                    notificationsQueue,
                    tokenSigner,
                    docAppPrivateKeyJwtSigner,
                    configurationParameters,
                    pendingEmailCheckQueue);

    protected static final ConfigurationService TXMA_ENABLED_CONFIGURATION_SERVICE =
            new IntegrationTestConfigurationService(
                    notificationsQueue,
                    tokenSigner,
                    docAppPrivateKeyJwtSigner,
                    configurationParameters,
                    pendingEmailCheckQueue) {

                @Override
                public String getTxmaAuditQueueUrl() {
                    return txmaAuditQueue.getQueueUrl();
                }
            };

    protected static final ConfigurationService
            REAUTH_SIGNOUT_AND_TXMA_ENABLED_CONFIGUARION_SERVICE =
                    new IntegrationTestConfigurationService(
                            notificationsQueue,
                            tokenSigner,
                            docAppPrivateKeyJwtSigner,
                            configurationParameters,
                            pendingEmailCheckQueue) {
                        @Override
                        public String getTxmaAuditQueueUrl() {
                            return txmaAuditQueue.getQueueUrl();
                        }

                        @Override
                        public boolean isReauthSignoutEnabled() {
                            return true;
                        }
                    };

    protected RequestHandler<Q, S> handler;
    protected final Json objectMapper = SerializationService.getInstance();
    protected final Context context = mock(Context.class);

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
    protected static final AccountModifiersStoreExtension accountModifiersStore =
            new AccountModifiersStoreExtension();

    @RegisterExtension
    protected static final CommonPasswordsExtension commonPasswords =
            new CommonPasswordsExtension();

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
        headers.put(TXMA_AUDIT_ENCODED_HEADER, ENCODED_DEVICE_INFORMATION);

        clientSessionId.ifPresent(id -> headers.put("Client-Session-Id", id));
        persistentSessionId.ifPresent(id -> headers.put("di-persistent-session-id", id));
        headers.put(TXMA_AUDIT_ENCODED_HEADER, "base64 encoded");
        return headers;
    }

    public static void setUpClientSession(
            String emailAddress,
            String clientSessionId,
            ClientID clientId,
            String clientName,
            URI redirectUri)
            throws Json.JsonException {

        var authRequest =
                new AuthenticationRequest.Builder(
                                ResponseType.CODE,
                                new Scope(OIDCScopeValue.OPENID),
                                new ClientID(clientId),
                                URI.create("http://localhost/redirect"))
                        .nonce(new Nonce())
                        .build();
        redis.createClientSession(clientSessionId, clientName, authRequest.toParameters());
        clientStore.registerClient(
                clientId.getValue(),
                clientName,
                singletonList(redirectUri.toString()),
                singletonList(emailAddress),
                new Scope(OIDCScopeValue.OPENID).toStringList(),
                Base64.getMimeEncoder()
                        .encodeToString(
                                KeyPairHelper.GENERATE_RSA_KEY_PAIR().getPublic().getEncoded()),
                singletonList("http://localhost/post-redirect-logout"),
                "http://example.com",
                valueOf(ServiceType.MANDATORY),
                "https://test.com",
                "public");
    }

    protected HttpCookie buildSessionCookie(String sessionID, String clientSessionID) {
        return new HttpCookie("gs", sessionID + "." + clientSessionID);
    }

    public static class IntegrationTestConfigurationService extends ConfigurationService {

        private final SqsQueueExtension notificationQueue;
        private SqsQueueExtension pendingEmailCheckQueue;
        private final TokenSigningExtension tokenSigningKey;
        private final TokenSigningExtension docAppPrivateKeyJwtSigner;

        public IntegrationTestConfigurationService(
                SqsQueueExtension notificationQueue,
                TokenSigningExtension tokenSigningKey,
                TokenSigningExtension docAppPrivateKeyJwtSigner,
                ParameterStoreExtension parameterStoreExtension) {
            super(parameterStoreExtension.getClient());
            this.notificationQueue = notificationQueue;
            this.tokenSigningKey = tokenSigningKey;
            this.docAppPrivateKeyJwtSigner = docAppPrivateKeyJwtSigner;
        }

        public IntegrationTestConfigurationService(
                SqsQueueExtension notificationQueue,
                TokenSigningExtension tokenSigningKey,
                TokenSigningExtension docAppPrivateKeyJwtSigner,
                ParameterStoreExtension parameterStoreExtension,
                SqsQueueExtension pendingEmailCheckQueue) {
            super(parameterStoreExtension.getClient());
            this.notificationQueue = notificationQueue;
            this.tokenSigningKey = tokenSigningKey;
            this.docAppPrivateKeyJwtSigner = docAppPrivateKeyJwtSigner;
            this.pendingEmailCheckQueue = pendingEmailCheckQueue;
        }

        public IntegrationTestConfigurationService(
                SqsQueueExtension notificationQueue,
                TokenSigningExtension tokenSigningKey,
                TokenSigningExtension docAppPrivateKeyJwtSigner,
                ParameterStoreExtension parameterStoreExtension,
                SystemService systemService,
                SqsQueueExtension pendingEmailCheckQueue) {
            super(parameterStoreExtension.getClient());
            this.notificationQueue = notificationQueue;
            this.tokenSigningKey = tokenSigningKey;
            this.docAppPrivateKeyJwtSigner = docAppPrivateKeyJwtSigner;
            super.systemService = systemService;
            this.pendingEmailCheckQueue = pendingEmailCheckQueue;
        }

        public IntegrationTestConfigurationService(
                SqsQueueExtension notificationQueue,
                TokenSigningExtension tokenSigningKey,
                TokenSigningExtension docAppPrivateKeyJwtSigner,
                ParameterStoreExtension parameterStoreExtension,
                SystemService systemService) {
            super(parameterStoreExtension.getClient());
            this.notificationQueue = notificationQueue;
            this.tokenSigningKey = tokenSigningKey;
            this.docAppPrivateKeyJwtSigner = docAppPrivateKeyJwtSigner;
            super.systemService = systemService;
        }

        @Override
        public String getEmailQueueUri() {
            return notificationQueue.getQueueUrl();
        }

        @Override
        public String getPendingEmailCheckQueueUri() {
            return pendingEmailCheckQueue.getQueueUrl();
        }

        @Override
        public String getTokenSigningKeyAlias() {
            return tokenSigningKey.getKeyAlias();
        }

        @Override
        public String getDocAppTokenSigningKeyAlias() {
            return docAppPrivateKeyJwtSigner.getKeyAlias();
        }

        @Override
        public String getFrontendBaseUrl() {
            return "http://localhost:3000/reset-password?code=";
        }
    }
}
