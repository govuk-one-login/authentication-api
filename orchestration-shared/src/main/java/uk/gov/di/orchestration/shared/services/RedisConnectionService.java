package uk.gov.di.orchestration.shared.services;

import io.lettuce.core.RedisClient;
import io.lettuce.core.RedisURI;
import io.lettuce.core.TransactionResult;
import io.lettuce.core.api.StatefulRedisConnection;
import io.lettuce.core.api.sync.RedisCommands;
import io.lettuce.core.api.sync.RedisServerCommands;
import org.apache.commons.pool2.impl.GenericObjectPool;
import org.apache.commons.pool2.impl.GenericObjectPoolConfig;

import java.util.Optional;

import static io.lettuce.core.support.ConnectionPoolSupport.createGenericObjectPool;
import static uk.gov.di.orchestration.shared.helpers.InstrumentationHelper.segmentedFunctionCall;

public class RedisConnectionService {

    public static final String REDIS_CONNECTION_ERROR = "Error getting Redis connection";
    private static RedisConnectionService instance;

    private final GenericObjectPool<StatefulRedisConnection<String, String>> pool;

    private RedisConnectionService(
            String host, int port, boolean useSsl, Optional<String> password) {
        RedisURI.Builder builder = RedisURI.builder().withHost(host).withPort(port).withSsl(useSsl);
        password.ifPresent(s -> builder.withPassword(s.toCharArray()));
        RedisURI redisURI = builder.build();
        RedisClient client = RedisClient.create(redisURI);
        this.pool = createGenericObjectPool(client::connect, new GenericObjectPoolConfig<>());
        warmUp();
    }

    private RedisConnectionService(ConfigurationService configurationService) {
        this(
                configurationService.getRedisHost(),
                configurationService.getRedisPort(),
                configurationService.getUseRedisTLS(),
                configurationService.getRedisPassword());
    }

    public static RedisConnectionService getInstance(ConfigurationService configurationService) {
        if (instance == null) {
            instance = new RedisConnectionService(configurationService);
        }
        return instance;
    }

    @FunctionalInterface
    private interface RedisFunction<T> {
        T getResult(RedisCommands<String, String> commands);
    }

    private <T> T executeCommand(RedisFunction<T> callable) {
        try (StatefulRedisConnection<String, String> connection =
                segmentedFunctionCall("Redis: getConnection", () -> pool.borrowObject())) {
            return callable.getResult(connection.sync());
        } catch (Exception e) {
            throw new RedisConnectionException(REDIS_CONNECTION_ERROR, e);
        }
    }

    public void saveWithExpiry(final String key, final String value, final long expiry) {
        segmentedFunctionCall(
                "Redis: saveWithExpiry",
                () -> executeCommand(commands -> commands.setex(key, expiry, value)));
    }

    public boolean keyExists(final String key) {
        return segmentedFunctionCall(
                "Redis: keyExists", () -> executeCommand(commands -> commands.exists(key) == 1));
    }

    public String getValue(final String key) {
        return segmentedFunctionCall(
                "Redis: getValue", () -> executeCommand(commands -> commands.get(key)));
    }

    public long deleteValue(final String key) {
        return segmentedFunctionCall(
                "Redis: deleteValue", () -> executeCommand(commands -> commands.del(key)));
    }

    public String popValue(final String key) {
        return segmentedFunctionCall(
                "Redis: popValue",
                () ->
                        executeCommand(
                                commands -> {
                                    commands.multi();
                                    commands.get(key);
                                    commands.del(key);
                                    TransactionResult result = commands.exec();
                                    return result.get(0);
                                }));
    }

    private void warmUp() {
        segmentedFunctionCall(
                "Redis: warmUp", () -> executeCommand(RedisServerCommands::clientGetname));
    }

    public static class RedisConnectionException extends RuntimeException {
        public RedisConnectionException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
