package uk.gov.di.services;

import io.lettuce.core.RedisClient;
import io.lettuce.core.RedisURI;
import io.lettuce.core.TransactionResult;
import io.lettuce.core.api.StatefulRedisConnection;
import io.lettuce.core.api.sync.RedisCommands;

import java.util.Optional;

public class RedisConnectionService implements AutoCloseable {

    private final RedisClient client;

    public RedisConnectionService(
            String host, int port, boolean useSsl, Optional<String> password) {
        RedisURI.Builder builder = RedisURI.builder().withHost(host).withPort(port).withSsl(useSsl);
        if (password.isPresent()) builder.withPassword(password.get().toCharArray());
        RedisURI redisURI = builder.build();
        this.client = RedisClient.create(redisURI);
    }

    public RedisConnectionService(ConfigurationService configurationService) {
        this(
                configurationService.getRedisHost(),
                configurationService.getRedisPort(),
                configurationService.getUseRedisTLS(),
                configurationService.getRedisPassword());
    }

    public void saveWithExpiry(String key, String value, long expiry) {
        try (StatefulRedisConnection<String, String> connection = client.connect()) {
            connection.sync().setex(key, expiry, value);
        }
    }

    public boolean keyExists(String key) {
        try (StatefulRedisConnection<String, String> connection = client.connect()) {
            return (connection.sync().exists(key) == 1);
        }
    }

    public String getValue(String key) {
        try (StatefulRedisConnection<String, String> connection = client.connect()) {
            return connection.sync().get(key);
        }
    }

    public long deleteValue(String key) {
        try (StatefulRedisConnection<String, String> connection = client.connect()) {
            return connection.sync().del(key);
        }
    }

    public String popValue(String key) {
        try (StatefulRedisConnection<String, String> connection = client.connect()) {
            RedisCommands<String, String> commands = connection.sync();
            commands.multi();
            commands.get(key);
            commands.del(key);
            TransactionResult result = commands.exec();
            return result.get(0);
        }
    }

    @Override
    public void close() {
        client.shutdown();
    }
}
