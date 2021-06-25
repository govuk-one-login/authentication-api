package uk.gov.di.services;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.lettuce.core.RedisClient;
import io.lettuce.core.RedisURI;
import io.lettuce.core.api.StatefulRedisConnection;
import uk.gov.di.entity.Session;

import java.io.IOException;
import java.util.Optional;

public class RedisConnectionService implements AutoCloseable {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final RedisClient client;
    private final long sessionExpiry;

    public RedisConnectionService(
            String host, int port, boolean useSsl, Optional<String> password, long sessionExpiry) {
        RedisURI.Builder builder = RedisURI.builder().withHost(host).withPort(port).withSsl(useSsl);
        if (password.isPresent()) builder.withPassword(password.get().toCharArray());
        RedisURI redisURI = builder.build();
        this.client = RedisClient.create(redisURI);
        this.sessionExpiry = sessionExpiry;
    }

    public RedisConnectionService(ConfigurationService configurationService) {
        this(
                configurationService.getRedisHost(),
                configurationService.getRedisPort(),
                configurationService.getUseRedisTLS(),
                configurationService.getRedisPassword(),
                configurationService.getSessionExpiry());
    }

    public void saveSession(Session session) throws IOException {
        saveWithExpiry(
                session.getSessionId(), objectMapper.writeValueAsString(session), sessionExpiry);
    }

    public void saveCodeWithExpiry(String key, String value, long expiry) {
        saveWithExpiry(key, value, expiry);
    }

    public void saveWithExpiry(String key, String value, long expiry) {
        try (StatefulRedisConnection<String, String> connection = client.connect()) {
            connection.sync().setex(key, expiry, value);
        }
    }

    public Session loadSession(String sessionId) throws IOException {
        try (StatefulRedisConnection<String, String> connection = client.connect()) {
            String result = connection.sync().get(sessionId);
            return objectMapper.readValue(result, Session.class);
        }
    }

    public boolean sessionExists(String sessionId) {
        try (StatefulRedisConnection<String, String> connection = client.connect()) {
            return (connection.sync().exists(sessionId) == 1);
        }
    }

    public String getValue(String key) {
        try (StatefulRedisConnection<String, String> connection = client.connect()) {
            return connection.sync().get(key);
        }
    }

    @Override
    public void close() {
        client.shutdown();
    }
}
