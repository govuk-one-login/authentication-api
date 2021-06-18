package uk.gov.di.services;

import uk.gov.di.entity.Session;

import java.util.Map;
import java.util.Optional;

public class SessionService {

    private static final String SESSION_ID_HEADER = "Session-Id";

    private final ConfigurationService configurationService;

    public SessionService(ConfigurationService configurationService) {
        this.configurationService = configurationService;
    }

    public Session createSession() {
        return new Session();
    }

    public void save(Session session) {
        try (RedisConnectionService redis = getRedisConnection()) {
            redis.saveSession(session);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public Optional<Session> getSessionFromRequestHeaders(Map<String, String> headers) {
        if (headers == null || headers.isEmpty() || !headers.containsKey(SESSION_ID_HEADER)) {
            return Optional.empty();
        }
        try (RedisConnectionService redis = getRedisConnection()) {
            String sessionId = headers.get(SESSION_ID_HEADER);
            if (redis.sessionExists(sessionId)) {
                return Optional.of(redis.loadSession(sessionId));
            }
            return Optional.empty();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private RedisConnectionService getRedisConnection() {
        return new RedisConnectionService(
                configurationService.getRedisHost(),
                configurationService.getRedisPort(),
                configurationService.getUseRedisTLS(),
                configurationService.getRedisPassword(),
                configurationService.getSessionExpiry());
    }
}
