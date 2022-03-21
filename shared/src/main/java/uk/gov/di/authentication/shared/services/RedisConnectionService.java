package uk.gov.di.authentication.shared.services;

import io.lettuce.core.RedisClient;
import io.lettuce.core.RedisURI;
import io.lettuce.core.TransactionResult;
import io.lettuce.core.api.StatefulRedisConnection;
import io.lettuce.core.api.sync.RedisCommands;
import org.apache.commons.pool2.impl.GenericObjectPool;
import org.apache.commons.pool2.impl.GenericObjectPoolConfig;

import java.util.Optional;

import static io.lettuce.core.support.ConnectionPoolSupport.createGenericObjectPool;

public class RedisConnectionService implements AutoCloseable {

    private final RedisClient client;

    private final GenericObjectPool<StatefulRedisConnection<String, String>> pool;

    public RedisConnectionService(
            String host, int port, boolean useSsl, Optional<String> password) {
        RedisURI.Builder builder = RedisURI.builder().withHost(host).withPort(port).withSsl(useSsl);
        password.ifPresent(s -> builder.withPassword(s.toCharArray()));
        RedisURI redisURI = builder.build();
        this.client = RedisClient.create(redisURI);
        this.pool = createGenericObjectPool(client::connect, new GenericObjectPoolConfig<>());
        warmUp();
    }

    public RedisConnectionService(ConfigurationService configurationService) {
        this(
                configurationService.getRedisHost(),
                configurationService.getRedisPort(),
                configurationService.getUseRedisTLS(),
                configurationService.getRedisPassword());
    }

    public void saveWithExpiry(String key, String value, long expiry) {
        try (StatefulRedisConnection<String, String> connection = pool.borrowObject()) {
            connection.sync().setex(key, expiry, value);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public boolean keyExists(String key) {
        try (StatefulRedisConnection<String, String> connection = pool.borrowObject()) {
            return (connection.sync().exists(key) == 1);
        } catch (Exception e) {
            return false;
        }
    }

    public String getValue(String key) {
        try (StatefulRedisConnection<String, String> connection = pool.borrowObject()) {
            return connection.sync().get(key);
        } catch (Exception e) {
            return null;
        }
    }

    public long deleteValue(String key) {
        try (StatefulRedisConnection<String, String> connection = pool.borrowObject()) {
            return connection.sync().del(key);
        } catch (Exception e) {
            return 0;
        }
    }

    public String popValue(String key) {
        try (StatefulRedisConnection<String, String> connection = pool.borrowObject()) {
            RedisCommands<String, String> commands = connection.sync();
            commands.multi();
            commands.get(key);
            commands.del(key);
            TransactionResult result = commands.exec();
            return result.get(0);
        } catch (Exception e) {
            return null;
        }
    }

    private void warmUp() {
        try (StatefulRedisConnection<String, String> connection = pool.borrowObject()) {
            connection.sync().clientGetname();
        } catch (Exception e) {

        }
    }

    @Override
    public void close() {
        pool.close();
        client.shutdown();
    }
}
