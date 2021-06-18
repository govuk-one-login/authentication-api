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

    public void saveSession(Session session) throws IOException {
        try (StatefulRedisConnection<String, String> connection = client.connect()) {
            connection
                    .sync()
                    .setex(
                            session.getSessionId(),
                            sessionExpiry,
                            objectMapper.writeValueAsString(session));
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

    @Override
    public void close() {
        client.shutdown();
    }
}
