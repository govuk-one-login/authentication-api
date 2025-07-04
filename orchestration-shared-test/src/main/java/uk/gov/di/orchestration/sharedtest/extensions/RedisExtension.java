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
import uk.gov.di.orchestration.shared.serialization.Json;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.RedisConnectionService;

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
