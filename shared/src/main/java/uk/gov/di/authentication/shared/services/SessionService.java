package uk.gov.di.authentication.shared.services;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.helpers.CookieHelper;
import uk.gov.di.authentication.shared.helpers.InputSanitiser;
import uk.gov.di.authentication.shared.helpers.JsonUpdateHelper;
import uk.gov.di.authentication.shared.serialization.Json;

import java.util.Map;
import java.util.Optional;

import static uk.gov.di.authentication.shared.domain.RequestHeaders.SESSION_ID_HEADER;
import static uk.gov.di.authentication.shared.helpers.RequestHeaderHelper.getOptionalHeaderValueFromHeaders;

public class SessionService {

    private static final Logger LOG = LogManager.getLogger(SessionService.class);

    private static final Json OBJECT_MAPPER = SerializationService.getInstance();

    private final ConfigurationService configurationService;
    private final RedisConnectionService redisConnectionService;
    private final CookieHelper cookieHelper;

    public SessionService(
            ConfigurationService configurationService,
            RedisConnectionService redisConnectionService) {
        this.configurationService = configurationService;
        this.redisConnectionService = redisConnectionService;
        this.cookieHelper = new CookieHelper();
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

    public void storeOrUpdateSession(Session session, String sessionId) {
        try {
            var newSession = OBJECT_MAPPER.writeValueAsString(session);
            if (redisConnectionService.keyExists(sessionId)) {
                var oldSession = redisConnectionService.getValue(sessionId);
                newSession = JsonUpdateHelper.updateJson(oldSession, newSession);
            }

            redisConnectionService.saveWithExpiry(
                    sessionId, newSession, configurationService.getSessionExpiry());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public Optional<Session> getSessionFromRequestHeaders(Map<String, String> headers) {
        Optional<String> sessionId =
                getOptionalHeaderValueFromHeaders(
                        headers,
                        SESSION_ID_HEADER,
                        configurationService.getHeadersCaseInsensitive());

        if (sessionId.isEmpty()) {
            LOG.warn("Value not found for Session-Id header");
        }

        return sessionId
                .flatMap(InputSanitiser::sanitiseBase64)
                .flatMap(
                        id -> {
                            try {
                                return getSession(id);
                            } catch (Exception e) {
                                throw new RuntimeException(e);
                            }
                        });
    }

    public Optional<Session> getSessionFromSessionCookie(Map<String, String> headers) {
        try {
            Optional<CookieHelper.SessionCookieIds> ids = cookieHelper.parseSessionCookie(headers);
            return ids.flatMap(s -> getSession(s.getSessionId()));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public void deleteSessionFromRedis(String sessionId) {
        redisConnectionService.deleteValue(sessionId);
    }

    public Optional<Session> getSession(String sessionId) {
        String serializedSession = redisConnectionService.getValue(sessionId);
        return Optional.ofNullable(serializedSession)
                .map(s -> OBJECT_MAPPER.readValueUnchecked(s, Session.class));
    }
}
