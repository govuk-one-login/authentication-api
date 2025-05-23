package uk.gov.di.orchestration.shared.services;

import uk.gov.di.orchestration.shared.entity.Session;
import uk.gov.di.orchestration.shared.helpers.JsonUpdateHelper;
import uk.gov.di.orchestration.shared.serialization.Json;

public class SessionService {

    private static final Json OBJECT_MAPPER = SerializationService.getInstance();

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

    public Session copySessionForMaxAge(Session previousSession) {
        return new Session(previousSession);
    }

    public void storeOrUpdateSession(Session session, String sessionId) {
        storeOrUpdateSession(session, sessionId, sessionId);
    }

    private void storeOrUpdateSession(Session session, String oldSessionId, String newSessionId) {
        try {
            var newSession = OBJECT_MAPPER.writeValueAsString(session);
            if (redisConnectionService.keyExists(oldSessionId)) {
                var oldSession = redisConnectionService.getValue(oldSessionId);
                newSession = JsonUpdateHelper.updateJson(oldSession, newSession);
            }

            redisConnectionService.saveWithExpiry(
                    newSessionId, newSession, configurationService.getSessionExpiry());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public Session updateWithNewSessionId(
            Session session, String oldSessionId, String newSessionId) {
        try {
            storeOrUpdateSession(session, oldSessionId, newSessionId);
            redisConnectionService.deleteValue(oldSessionId);
            return session;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
