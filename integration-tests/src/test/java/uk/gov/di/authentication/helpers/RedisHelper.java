package uk.gov.di.authentication.helpers;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import uk.gov.di.entity.ClientSession;
import uk.gov.di.entity.Session;
import uk.gov.di.entity.SessionState;
import uk.gov.di.helpers.IdGenerator;
import uk.gov.di.services.CodeGeneratorService;
import uk.gov.di.services.CodeStorageService;
import uk.gov.di.services.RedisConnectionService;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static uk.gov.di.entity.NotificationType.VERIFY_EMAIL;
import static uk.gov.di.entity.NotificationType.VERIFY_PHONE_NUMBER;

public class RedisHelper {

    private static final String REDIS_HOST =
            System.getenv().getOrDefault("REDIS_HOST", "localhost");
    private static final Optional<String> REDIS_PASSWORD =
            Optional.ofNullable(System.getenv("REDIS_PASSWORD"));
    private static final ObjectMapper OBJECT_MAPPER =
            JsonMapper.builder().addModule(new JavaTimeModule()).build();

    public static String createSession(String sessionId) throws IOException {
        try (RedisConnectionService redis =
                new RedisConnectionService(REDIS_HOST, 6379, false, REDIS_PASSWORD)) {
            Session session = new Session(sessionId);
            redis.saveWithExpiry(
                    session.getSessionId(), OBJECT_MAPPER.writeValueAsString(session), 1800);
            return session.getSessionId();
        }
    }

    public static String createSession() throws IOException {
        return createSession(IdGenerator.generate());
    }

    public static void addAuthRequestToSession(
            String clientSessionId, String sessionId, Map<String, List<String>> authRequest) {
        try (RedisConnectionService redis =
                new RedisConnectionService(REDIS_HOST, 6379, false, REDIS_PASSWORD)) {
            Session session = OBJECT_MAPPER.readValue(redis.getValue(sessionId), Session.class);
            session.setClientSession(
                    clientSessionId, new ClientSession(authRequest, LocalDateTime.now()));
            redis.saveWithExpiry(
                    session.getSessionId(), OBJECT_MAPPER.writeValueAsString(session), 1800);

        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static void addIDTokenToSession(
            String sessionId, String clientSessionId, String idTokenHint) {
        try (RedisConnectionService redis =
                new RedisConnectionService(REDIS_HOST, 6379, false, REDIS_PASSWORD)) {
            Session session = OBJECT_MAPPER.readValue(redis.getValue(sessionId), Session.class);
            session.getClientSessions().get(clientSessionId).setIdTokenHint(idTokenHint);
            redis.saveWithExpiry(
                    session.getSessionId(), OBJECT_MAPPER.writeValueAsString(session), 1800);

        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static void addEmailToSession(String sessionId, String emailAddress) {
        try (RedisConnectionService redis =
                new RedisConnectionService(REDIS_HOST, 6379, false, REDIS_PASSWORD)) {
            Session session = OBJECT_MAPPER.readValue(redis.getValue(sessionId), Session.class);
            session.setEmailAddress(emailAddress);
            redis.saveWithExpiry(
                    session.getSessionId(), OBJECT_MAPPER.writeValueAsString(session), 1800);

        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static void setSessionState(String sessionId, SessionState state) {
        try (RedisConnectionService redis =
                new RedisConnectionService(REDIS_HOST, 6379, false, REDIS_PASSWORD)) {
            Session session = OBJECT_MAPPER.readValue(redis.getValue(sessionId), Session.class);
            session.setState(state);
            redis.saveWithExpiry(
                    session.getSessionId(), OBJECT_MAPPER.writeValueAsString(session), 1800);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static String generateAndSaveEmailCode(String email, long codeExpiryTime) {
        try (RedisConnectionService redis =
                new RedisConnectionService(REDIS_HOST, 6379, false, REDIS_PASSWORD)) {

            var code = new CodeGeneratorService().sixDigitCode();
            new CodeStorageService(redis).saveOtpCode(email, code, codeExpiryTime, VERIFY_EMAIL);

            return code;
        }
    }

    public static String generateAndSavePhoneNumberCode(String email, long codeExpiryTime) {
        try (RedisConnectionService redis =
                new RedisConnectionService(REDIS_HOST, 6379, false, REDIS_PASSWORD)) {

            var code = new CodeGeneratorService().sixDigitCode();
            new CodeStorageService(redis)
                    .saveOtpCode(email, code, codeExpiryTime, VERIFY_PHONE_NUMBER);

            return code;
        }
    }

    public static void blockPhoneCode(String email, String sessionId) {
        try (RedisConnectionService redis =
                new RedisConnectionService(REDIS_HOST, 6379, false, REDIS_PASSWORD)) {

            new CodeStorageService(redis).saveCodeBlockedForSession(email, sessionId, 10);
        }
    }
}
