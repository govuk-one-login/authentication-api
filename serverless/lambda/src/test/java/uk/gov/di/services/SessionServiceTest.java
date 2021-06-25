package uk.gov.di.services;

import org.junit.jupiter.api.Test;
import uk.gov.di.entity.Session;

import java.util.Collections;
import java.util.Map;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
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

    @Test
    public void shouldRetrieveSessionUsingRequestHeaders() {
        var serialisedSession =
                "{\"session_id\":\"session-id\",\"authentication_request\":null,\"state\":\"NEW\",\"email_address\":null}";

        when(redis.keyExists("session-id")).thenReturn(true);
        when(redis.getValue("session-id")).thenReturn(serialisedSession);

        var sessionInRedis =
                sessionService.getSessionFromRequestHeaders(Map.of("Session-Id", "session-id"));

        sessionInRedis.ifPresentOrElse(
                session -> assertThat(session.getSessionId(), is("session-id")),
                () -> fail("Could not retrieve result"));
    }

    @Test
    public void shouldNotRetrieveSessionWithNoHeaders() {
        var session = sessionService.getSessionFromRequestHeaders(Collections.emptyMap());
        assertTrue(session.isEmpty());
    }

    @Test
    public void shouldNotRetrieveSessionWithNullHeaders() {
        var session = sessionService.getSessionFromRequestHeaders(null);
        assertTrue(session.isEmpty());
    }

    @Test
    public void shouldNotRetrieveSessionWithMissingHeader() {
        var session = sessionService.getSessionFromRequestHeaders(Map.of("Something", "Else"));
        assertTrue(session.isEmpty());
    }

    @Test
    public void shouldNotRetrieveSessionIfNotPresentInRedis() {
        when(redis.keyExists("session-id")).thenReturn(false);

        var session = sessionService.getSessionFromRequestHeaders(Map.of("Session-Id", "session-id"));

        assertTrue(session.isEmpty());
    }
}
