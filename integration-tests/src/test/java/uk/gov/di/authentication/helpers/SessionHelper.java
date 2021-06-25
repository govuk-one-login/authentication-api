package uk.gov.di.authentication.helpers;

import uk.gov.di.entity.Session;
import uk.gov.di.helpers.IdGenerator;
import uk.gov.di.services.CodeGeneratorService;
import uk.gov.di.services.CodeStorageService;
import uk.gov.di.services.RedisConnectionService;

import java.io.IOException;
import java.util.Optional;

public class SessionHelper {

    private static final String REDIS_HOST =
            System.getenv().getOrDefault("REDIS_HOST", "localhost");
    private static final Optional<String> REDIS_PASSWORD =
            Optional.ofNullable(System.getenv("REDIS_PASSWORD"));

    public static String createSession() throws IOException {
        try (RedisConnectionService redis =
                new RedisConnectionService(REDIS_HOST, 6379, false, REDIS_PASSWORD, 1800)) {
            Session session = new Session(IdGenerator.generate());
            redis.saveSession(session);
            return session.getSessionId();
        }
    }

    public static void addEmailToSession(String sessionId, String emailAddress) {
        try (RedisConnectionService redis =
                new RedisConnectionService(REDIS_HOST, 6379, false, REDIS_PASSWORD, 1800)) {
            Session session = redis.loadSession(sessionId);
            session.setEmailAddress(emailAddress);
            redis.saveSession(session);

        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static String generateAndSaveEmailCode(String email, long codeExpiryTime) {
        try (RedisConnectionService redis =
                new RedisConnectionService(REDIS_HOST, 6379, false, REDIS_PASSWORD, 1800)) {

            var code = new CodeGeneratorService().sixDigitCode();
            new CodeStorageService(redis).saveEmailCode(email, code, codeExpiryTime);

            return code;
        }
    }
}
