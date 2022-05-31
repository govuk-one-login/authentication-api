package uk.gov.di.authentication.shared.services;

import io.lettuce.core.ReadFrom;
import io.lettuce.core.RedisClient;
import io.lettuce.core.RedisURI;
import io.lettuce.core.TransactionResult;
import io.lettuce.core.api.StatefulRedisConnection;
import io.lettuce.core.api.sync.RedisCommands;
import io.lettuce.core.api.sync.RedisServerCommands;
import io.lettuce.core.codec.StringCodec;
import io.lettuce.core.masterreplica.MasterReplica;
import io.lettuce.core.masterreplica.StatefulRedisMasterReplicaConnection;
import io.lettuce.core.support.ConnectionPoolSupport;
import org.apache.commons.pool2.impl.SoftReferenceObjectPool;

import java.util.List;
import java.util.Optional;

import static uk.gov.di.authentication.shared.helpers.InstrumentationHelper.segmentedFunctionCall;

public class RedisConnectionService implements AutoCloseable {

    public static final String REDIS_CONNECTION_ERROR = "Error getting Redis connection";
    private final RedisClient client;

    private final SoftReferenceObjectPool<StatefulRedisMasterReplicaConnection<String, String>>
            pool;

    public RedisConnectionService(List<RedisURI> nodes, boolean warmup) {
        this.client = RedisClient.create();
        this.pool =
                ConnectionPoolSupport.createSoftReferenceObjectPool(
                        () -> {
                            var connection = MasterReplica.connect(client, StringCodec.UTF8, nodes);
                            connection.setReadFrom(ReadFrom.REPLICA_PREFERRED);
                            return connection;
                        });
        if (warmup) warmUp();
    }

    public RedisConnectionService(
            String host, int port, boolean useSsl, Optional<String> password) {
        var builder = RedisURI.builder().withHost(host).withPort(port).withSsl(useSsl);
        password.ifPresent(s -> builder.withPassword(s.toCharArray()));
        RedisURI redisURI = builder.build();

        this.client = RedisClient.create();
        this.pool =
                ConnectionPoolSupport.createSoftReferenceObjectPool(
                        () -> MasterReplica.connect(client, StringCodec.UTF8, List.of(redisURI)));
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
