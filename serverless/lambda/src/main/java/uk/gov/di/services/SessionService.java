package uk.gov.di.services;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.entity.Session;
import uk.gov.di.helpers.IdGenerator;

import java.util.Map;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SessionService {

    private static final Logger LOGGER = LoggerFactory.getLogger(SessionService.class);

    private static final String SESSION_ID_HEADER = "Session-Id";
    public static final String REQUEST_COOKIE_HEADER = "Cookie";

    private static final ObjectMapper OBJECT_MAPPER =
            JsonMapper.builder().addModule(new JavaTimeModule()).build();

    private final ConfigurationService configurationService;
    private final RedisConnectionService redisConnectionService;

    public SessionService(
            ConfigurationService configurationService,
            RedisConnectionService redisConnectionService) {
        this.configurationService = configurationService;
        this.redisConnectionService = redisConnectionService;
    }

    public SessionService(ConfigurationService configurationService) {
        this(
                configurationService,
                new RedisConnectionService(
                        configurationService.getRedisHost(),
                        configurationService.getRedisPort(),
                        configurationService.getUseRedisTLS(),
                        configurationService.getRedisPassword()));
    }

    public Session createSession() {
        return new Session(IdGenerator.generate());
    }

    public String generateClientSessionID() {
        return IdGenerator.generate();
    }

    public void save(Session session) {
        try {
            redisConnectionService.saveWithExpiry(
                    session.getSessionId(),
                    OBJECT_MAPPER.writeValueAsString(session),
                    configurationService.getSessionExpiry());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public void updateSessionId(Session session) {
        try {

            String oldSessionId = session.getSessionId();
            session.setSessionId(IdGenerator.generate());
            save(session);
            redisConnectionService.deleteValue(oldSessionId);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public Optional<Session> getSessionFromRequestHeaders(Map<String, String> headers) {
        if (headers == null || headers.isEmpty() || !headers.containsKey(SESSION_ID_HEADER)) {
            return Optional.empty();
        }
        try {
            String sessionId = headers.get(SESSION_ID_HEADER);
            return readSessionFromRedis(sessionId);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public Optional<Session> getSessionFromSessionCookie(Map<String, String> headers) {
        if (headers == null
                || headers.isEmpty()
                || !headers.containsKey(REQUEST_COOKIE_HEADER)
                || headers.get(REQUEST_COOKIE_HEADER).isEmpty()) {
            return Optional.empty();
        }

        final String COOKIE_REGEX = "gs=(?<sid>[^.;]+)\\.(?<csid>[^.;]+);";

        try {
            String cookies = headers.getOrDefault(REQUEST_COOKIE_HEADER, "");

            LOGGER.debug("Session Cookie: {}", cookies);

            Matcher cookiesMatcher = Pattern.compile(COOKIE_REGEX).matcher(cookies);
            Optional<String> sid = Optional.empty();

            try {
                if (cookiesMatcher.find()) {
                    sid = Optional.ofNullable(cookiesMatcher.group("sid"));
                }
            } catch (IllegalStateException | IllegalArgumentException ise) {
                LOGGER.error("Unable to parse Session Cookie: {}", ise.getMessage());
                return Optional.empty();
            }
            return sid.flatMap(this::readSessionFromRedis);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public Optional<Session> readSessionFromRedis(String sessionId) {
        try {
            if (redisConnectionService.keyExists(sessionId)) {
                return Optional.of(
                        OBJECT_MAPPER.readValue(
                                redisConnectionService.getValue(sessionId), Session.class));
            } else {
                return Optional.empty();
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
