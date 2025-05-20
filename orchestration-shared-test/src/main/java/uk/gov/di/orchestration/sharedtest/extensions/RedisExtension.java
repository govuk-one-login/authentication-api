package uk.gov.di.orchestration.sharedtest.extensions;

import com.nimbusds.oauth2.sdk.id.State;
import io.lettuce.core.RedisClient;
import io.lettuce.core.RedisURI;
import io.lettuce.core.api.StatefulRedisConnection;
import org.junit.jupiter.api.extension.AfterAllCallback;
import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.Extension;
import org.junit.jupiter.api.extension.ExtensionContext;
import uk.gov.di.orchestration.shared.entity.ClientSession;
import uk.gov.di.orchestration.shared.entity.CredentialTrustLevel;
import uk.gov.di.orchestration.shared.entity.Session;
import uk.gov.di.orchestration.shared.helpers.IdGenerator;
import uk.gov.di.orchestration.shared.serialization.Json;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.RedisConnectionService;

import static uk.gov.di.orchestration.shared.services.ClientSessionService.CLIENT_SESSION_PREFIX;

public class RedisExtension
        implements Extension, BeforeAllCallback, AfterAllCallback, AfterEachCallback {
    private final ConfigurationService configurationService;

    private final Json objectMapper;

    private RedisConnectionService redis;
    private RedisClient client;

    public RedisExtension(Json objectMapper, ConfigurationService configurationService) {
        this.objectMapper = objectMapper;
        this.configurationService = configurationService;
    }

    public String createSession(String sessionId) throws Json.JsonException {
        Session session = new Session();
        redis.saveWithExpiry(sessionId, objectMapper.writeValueAsString(session), 3600);
        return sessionId;
    }

    public Session addSessionWithId(Session session, String sessionId) throws Json.JsonException {
        redis.saveWithExpiry(sessionId, objectMapper.writeValueAsString(session), 3600);
        return session;
    }

    public String createSession() throws Json.JsonException {
        return createSession(IdGenerator.generate());
    }

    public void addStateToRedis(State state, String sessionId) throws Json.JsonException {
        addStateToRedis("state:", state, sessionId);
    }

    public void addStateToRedis(String prefix, State state, String sessionId)
            throws Json.JsonException {
        redis.saveWithExpiry(prefix + sessionId, objectMapper.writeValueAsString(state), 3600);
    }

    public void addClientSessionAndStateToRedis(State state, String clientSessionId) {
        redis.saveWithExpiry("state:" + state.getValue(), clientSessionId, 3600);
    }

    public void setSessionCredentialTrustLevel(
            String sessionId, CredentialTrustLevel credentialTrustLevel) throws Json.JsonException {
        Session session = objectMapper.readValue(redis.getValue(sessionId), Session.class);
        session.setCurrentCredentialStrength(credentialTrustLevel);
        redis.saveWithExpiry(sessionId, objectMapper.writeValueAsString(session), 3600);
    }

    public Session getSession(String sessionId) throws Json.JsonException {
        return objectMapper.readValue(redis.getValue(sessionId), Session.class);
    }

    public void addToRedis(String key, String value, Long expiry) {
        redis.saveWithExpiry(key, value, expiry);
    }

    public String getFromRedis(String key) {
        return redis.getValue(key);
    }

    public void flushData() {
        try (StatefulRedisConnection<String, String> connection = client.connect()) {
            connection.sync().flushall();
        }
    }

    public void createClientSession(String clientSessionId, ClientSession clientSession)
            throws Json.JsonException {
        redis.saveWithExpiry(
                CLIENT_SESSION_PREFIX.concat(clientSessionId),
                objectMapper.writeValueAsString(clientSession),
                300);
    }

    @Override
    public void afterAll(ExtensionContext context) {
        redis.close();
        client.shutdown();
    }

    @Override
    public void beforeAll(ExtensionContext context) throws Exception {
        redis = new RedisConnectionService(configurationService);
        RedisURI.Builder builder =
                RedisURI.builder()
                        .withHost(configurationService.getRedisHost())
                        .withPort(configurationService.getRedisPort())
                        .withSsl(configurationService.getUseRedisTLS());
        configurationService
                .getRedisPassword()
                .ifPresent(redisPassword -> builder.withPassword(redisPassword.toCharArray()));
        RedisURI redisURI = builder.build();
        if (client != null) {
            client.shutdown();
        }
        client = RedisClient.create(redisURI);
    }

    @Override
    public void afterEach(ExtensionContext context) throws Exception {
        flushData();
    }
}
