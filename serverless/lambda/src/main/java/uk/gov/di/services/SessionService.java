package uk.gov.di.services;

import com.amazonaws.services.lambda.runtime.LambdaLogger;

import io.lettuce.core.RedisClient;
import io.lettuce.core.RedisURI;
import io.lettuce.core.api.StatefulRedisConnection;
import io.lettuce.core.api.sync.RedisStringCommands;
import uk.gov.di.entity.Session;

public class SessionService {

    private final ConfigurationService configService = new ConfigurationService();

    public Session createSession() {
        return new Session();
    }

    public void save(Session session, LambdaLogger logger) {

        RedisURI redisURI = RedisURI.builder()
                .withHost(configService.getRedisHost())
                .withPort(configService.getRedisPort())
                .withSsl(configService.getUseRedisTLS())
                .withPassword(configService.getRedisPassword().toCharArray())
                .build();
        logger.log("Creating Redis Client");
        RedisClient client = RedisClient.create(redisURI);
        try {
            logger.log("Opening Redis Connection");
            StatefulRedisConnection<String, String> connection = client.connect();
            logger.log("Creating command");
            RedisStringCommands<String, String> sync = connection.sync();
            logger.log("Executing set command");
            String result = sync.set(session.getSessionId(), "xyz");
            logger.log("Command result: " + result);
            logger.log("Closing connection");
            connection.close();
        } catch (Exception e) {
            logger.log("An error occurred: " + e.getMessage());
        } finally {
            logger.log("Shutting down client");
            client.shutdown();
        }
    }
}
