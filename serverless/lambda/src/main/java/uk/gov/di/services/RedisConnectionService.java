package uk.gov.di.services;

import com.amazonaws.services.lambda.runtime.LambdaLogger;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.lettuce.core.RedisClient;
import io.lettuce.core.RedisURI;
import io.lettuce.core.api.StatefulRedisConnection;
import io.lettuce.core.api.sync.RedisStringCommands;
import uk.gov.di.entity.Session;

import java.io.IOException;

public class RedisConnectionService implements AutoCloseable {

    private final ConfigurationService configService = new ConfigurationService();
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final RedisClient client;
    private final LambdaLogger logger;

    public RedisConnectionService(LambdaLogger logger) {
        this.logger = logger;
        RedisURI redisURI = RedisURI.builder()
                .withHost(configService.getRedisHost())
                .withPort(configService.getRedisPort())
                .withSsl(configService.getUseRedisTLS())
                .withPassword(configService.getRedisPassword().toCharArray())
                .build();
        client = RedisClient.create(redisURI);
    }

    public void saveSession(Session session) throws IOException {
        StatefulRedisConnection<String, String> connection = null;
        try {
            logger.log("Opening Redis Connection");
            connection = client.connect();
            RedisStringCommands<String, String> sync = connection.sync();
            sync.set(session.getSessionId(), objectMapper.writeValueAsString(this));
            logger.log("Closing connection");
        } finally {
            if (connection!=null && connection.isOpen()) {
                connection.close();
            }
        }
    }

    @Override
    public void close() throws Exception {
        logger.log("Shutting down client");
        client.shutdown();
    }
}
