package uk.gov.di.authentication.helpers;

import com.fasterxml.jackson.databind.ObjectMapper;
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
                new RedisConnectionService(REDIS_HOST, 6379, false, REDIS_PASSWORD)) {
            Session session = new Session(IdGenerator.generate());
            redis.saveWithExpiry(
                    session.getSessionId(), new ObjectMapper().writeValueAsString(session), 1800);
            return session.getSessionId();
        }
    }

    public static void addEmailToSession(String sessionId, String emailAddress) {
        try (RedisConnectionService redis =
                new RedisConnectionService(REDIS_HOST, 6379, false, REDIS_PASSWORD)) {
            Session session =
                    new ObjectMapper().readValue(redis.getValue(sessionId), Session.class);
            session.setEmailAddress(emailAddress);
            redis.saveWithExpiry(
                    session.getSessionId(), new ObjectMapper().writeValueAsString(session), 1800);

        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static String generateAndSaveEmailCode(String email, long codeExpiryTime) {
        try (RedisConnectionService redis =
                new RedisConnectionService(REDIS_HOST, 6379, false, REDIS_PASSWORD)) {

            var code = new CodeGeneratorService().sixDigitCode();
            new CodeStorageService(redis).saveEmailCode(email, code, codeExpiryTime);

            return code;
        }
    }

    public static String generateAndSavePhoneNumberCode(String email, long codeExpiryTime) {
        try (RedisConnectionService redis =
                new RedisConnectionService(REDIS_HOST, 6379, false, REDIS_PASSWORD)) {

            var code = new CodeGeneratorService().sixDigitCode();
            new CodeStorageService(redis).savePhoneNumberCode(email, code, codeExpiryTime);

            return code;
        }
    }
}
