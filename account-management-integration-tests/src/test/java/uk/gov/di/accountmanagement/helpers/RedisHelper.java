package uk.gov.di.accountmanagement.helpers;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import io.lettuce.core.RedisClient;
import io.lettuce.core.RedisURI;
import io.lettuce.core.api.StatefulRedisConnection;
import uk.gov.di.authentication.shared.entity.AuthCodeExchangeData;
import uk.gov.di.authentication.shared.entity.ClientSession;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.SessionState;
import uk.gov.di.authentication.shared.helpers.IdGenerator;
import uk.gov.di.authentication.shared.services.CodeGeneratorService;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.RedisConnectionService;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_EMAIL;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_PHONE_NUMBER;
import static uk.gov.di.authentication.shared.services.AuthorisationCodeService.AUTH_CODE_PREFIX;
import static uk.gov.di.authentication.shared.services.ClientSessionService.CLIENT_SESSION_PREFIX;

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
            String clientSessionId,
            String sessionId,
            Map<String, List<String>> authRequest,
            String email) {
        try (RedisConnectionService redis =
                new RedisConnectionService(REDIS_HOST, 6379, false, REDIS_PASSWORD)) {
            Session session = OBJECT_MAPPER.readValue(redis.getValue(sessionId), Session.class);
            session.addClientSession(clientSessionId);
            redis.saveWithExpiry(
                    session.getSessionId(), OBJECT_MAPPER.writeValueAsString(session), 1800);
            redis.saveWithExpiry(
                    CLIENT_SESSION_PREFIX.concat(clientSessionId),
                    OBJECT_MAPPER.writeValueAsString(
                            new ClientSession(authRequest, LocalDateTime.now())),
                    1800);

        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static void addIDTokenToSession(String clientSessionId, String idTokenHint) {
        try (RedisConnectionService redis =
                new RedisConnectionService(REDIS_HOST, 6379, false, REDIS_PASSWORD)) {

            ClientSession clientSession =
                    OBJECT_MAPPER.readValue(
                            redis.getValue(CLIENT_SESSION_PREFIX.concat(clientSessionId)),
                            ClientSession.class);
            clientSession.setIdTokenHint(idTokenHint);
            redis.saveWithExpiry(
                    CLIENT_SESSION_PREFIX.concat(clientSessionId),
                    OBJECT_MAPPER.writeValueAsString(clientSession),
                    1800);

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

    public static void addAccessTokenToRedis(String accessToken, String subject, Long expiry) {
        RedisConnectionService redis =
                new RedisConnectionService(REDIS_HOST, 6379, false, REDIS_PASSWORD);
        redis.saveWithExpiry(accessToken, subject, expiry);
    }

    public static void flushData() {
        RedisURI.Builder builder =
                RedisURI.builder().withHost(REDIS_HOST).withPort(6379).withSsl(false);
        if (REDIS_PASSWORD.isPresent()) builder.withPassword(REDIS_PASSWORD.get().toCharArray());
        RedisURI redisURI = builder.build();
        RedisClient client = RedisClient.create(redisURI);
        try (StatefulRedisConnection<String, String> connection = client.connect()) {
            connection.sync().flushall();
        }
        client.shutdown();
    }

    public static void addAuthCodeAndCreateClientSession(
            String authCode,
            String clientSessionId,
            String email,
            Map<String, List<String>> authRequest) {
        try (RedisConnectionService redis =
                new RedisConnectionService(REDIS_HOST, 6379, false, REDIS_PASSWORD)) {
            redis.saveWithExpiry(
                    AUTH_CODE_PREFIX.concat(authCode),
                    OBJECT_MAPPER.writeValueAsString(
                            new AuthCodeExchangeData()
                                    .setClientSessionId(clientSessionId)
                                    .setEmail(email)),
                    300);
            redis.saveWithExpiry(
                    CLIENT_SESSION_PREFIX.concat(clientSessionId),
                    OBJECT_MAPPER.writeValueAsString(
                            new ClientSession(authRequest, LocalDateTime.now())),
                    300);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static void createClientSession(
            String clientSessionId, Map<String, List<String>> authRequest) {
        try (RedisConnectionService redis =
                new RedisConnectionService(REDIS_HOST, 6379, false, REDIS_PASSWORD)) {
            redis.saveWithExpiry(
                    CLIENT_SESSION_PREFIX.concat(clientSessionId),
                    OBJECT_MAPPER.writeValueAsString(
                            new ClientSession(authRequest, LocalDateTime.now())),
                    300);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
