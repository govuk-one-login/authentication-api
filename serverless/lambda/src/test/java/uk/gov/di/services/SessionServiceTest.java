package uk.gov.di.services;

import org.junit.jupiter.api.Test;
import uk.gov.di.entity.Session;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class SessionServiceTest {

    private final RedisConnectionService redis = mock(RedisConnectionService.class);
    private final ConfigurationService configuration = mock(ConfigurationService.class);

    private final SessionService sessionService = new SessionService(configuration, redis);

    @Test
    public void shouldPersistSessionToRedisWithExpiry() {
        when(configuration.getSessionExpiry()).thenReturn(1234L);

        var session = new Session("session-id");
        sessionService.save(session);

        var serialisedSession =
                "{\"session_id\":\"session-id\",\"authentication_request\":null,\"state\":\"NEW\",\"email_address\":null}";

        verify(redis).saveWithExpiry("session-id", serialisedSession, 1234L);
    }
}
