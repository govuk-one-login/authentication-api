package uk.gov.di.authentication.shared.services;

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
import static uk.gov.di.authentication.shared.helpers.InstrumentationHelper.segmentedFunctionCall;

public class RedisConnectionService implements AutoCloseable {

    public static final String REDIS_CONNECTION_ERROR = "Error getting Redis connection";
    private final RedisClient client;

    private final GenericObjectPool<StatefulRedisConnection<String, String>> pool;

    public RedisConnectionService(
            String host, int port, boolean useSsl, Optional<String> password, boolean warmup) {
        RedisURI.Builder builder = RedisURI.builder().withHost(host).withPort(port).withSsl(useSsl);
        password.ifPresent(s -> builder.withPassword(s.toCharArray()));
        RedisURI redisURI = builder.build();
        this.client = RedisClient.create(redisURI);
        this.pool = createGenericObjectPool(client::connect, new GenericObjectPoolConfig<>());
        if (warmup) warmUp();
    }

    public RedisConnectionService(
            String host, int port, boolean useSsl, Optional<String> password) {
        this(host, port, useSsl, password, true);
    }

    public RedisConnectionService(ConfigurationService configurationService) {
        this(
                configurationService.getRedisHost(),
                configurationService.getRedisPort(),
                configurationService.getUseRedisTLS(),
                configurationService.getRedisPassword());
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

    public Long getTimeToLive(final String key) {
        return segmentedFunctionCall(
                "Redis: getTimeToLive", () -> executeCommand(commands -> commands.ttl(key)));
    }

    public boolean keyExists(final String key) {
        return segmentedFunctionCall(
                "Redis: keyExists", () -> executeCommand(commands -> commands.exists(key) == 1));
    }

    public String getValue(final String key) {
        return segmentedFunctionCall(
                "Redis: getValue", () -> executeCommand(commands -> commands.get(key)));
    }
    
    public java.util.List<String> scanKeys(final String pattern) {
        return segmentedFunctionCall(
                "Redis: scanKeys", 
                () -> executeCommand(commands -> {
                    java.util.List<String> keys = new java.util.ArrayList<>();
                    io.lettuce.core.ScanCursor cursor = io.lettuce.core.ScanCursor.INITIAL;
                    
                    do {
                        io.lettuce.core.KeyScanCursor<String> scanResult = commands.scan(
                                cursor, 
                                io.lettuce.core.ScanArgs.Builder.matches(pattern).limit(100));
                        keys.addAll(scanResult.getKeys());
                        cursor = scanResult;
                    } while (!cursor.isFinished());
                    
                    return keys;
                }));
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

    @Override
    public void close() {
        pool.close();
        client.shutdown();
    }

    public static class RedisConnectionException extends RuntimeException {
        public RedisConnectionException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
