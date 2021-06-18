package uk.gov.di.authentication.helpers;

import uk.gov.di.entity.Session;
import uk.gov.di.services.RedisConnectionService;

import java.io.IOException;
import java.util.Optional;

public class SessionHelper {
    public static String createSession() throws IOException {
        String redisHost = System.getenv().getOrDefault("REDIS_HOST", "localhost");
        Optional<String> redisPassword = Optional.ofNullable(System.getenv("REDIS_PASSWORD"));
        try (RedisConnectionService redis =
                new RedisConnectionService(redisHost, 6379, false, redisPassword, 1800)) {
            Session session = new Session();
            redis.saveSession(session);
            return session.getSessionId();
        }
    }
}
