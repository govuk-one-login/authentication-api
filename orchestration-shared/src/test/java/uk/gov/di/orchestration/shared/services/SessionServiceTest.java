package uk.gov.di.orchestration.shared.services;

import org.junit.jupiter.api.Test;
import uk.gov.di.orchestration.shared.entity.Session;
import uk.gov.di.orchestration.shared.serialization.Json;

import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class SessionServiceTest {

    private final RedisConnectionService redis = mock(RedisConnectionService.class);
    private final ConfigurationService configuration = mock(ConfigurationService.class);
    private final Json objectMapper = SerializationService.getInstance();

    private final SessionService sessionService = new SessionService(configuration, redis);

    @Test
    void shouldPersistSessionToRedisWithExpiry() throws Json.JsonException {
        when(configuration.getSessionExpiry()).thenReturn(1234L);

        var session = new Session();

        sessionService.storeOrUpdateSession(session, "session-id");

        verify(redis, times(1))
                .saveWithExpiry("session-id", objectMapper.writeValueAsString(session), 1234L);
    }

    @Test
    void shouldUpdateSessionIdInRedisAndDeleteOldKey() {
        var session = new Session();

        sessionService.storeOrUpdateSession(session, "session-id");
        sessionService.updateWithNewSessionId(session, "session-id", "new-session-id");

        verify(redis).saveWithExpiry(eq("session-id"), anyString(), anyLong());
        verify(redis).saveWithExpiry(eq("new-session-id"), anyString(), anyLong());
        verify(redis).deleteValue("session-id");
    }

    @Test
    void shouldDeleteSessionIdFromRedis() {
        var session = new Session();

        sessionService.storeOrUpdateSession(session, "session-id");
        sessionService.deleteStoredSession("session-id");

        verify(redis).deleteValue("session-id");
    }
}
