package uk.gov.di.services;

import org.junit.jupiter.api.Test;
import uk.gov.di.entity.Session;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.services.SessionService.REQUEST_COOKIE_HEADER;

class SessionServiceTest {

    private final RedisConnectionService redis = mock(RedisConnectionService.class);
    private final ConfigurationService configuration = mock(ConfigurationService.class);

    private final SessionService sessionService = new SessionService(configuration, redis);

    @Test
    public void shouldPersistSessionToRedisWithExpiry() {
        when(configuration.getSessionExpiry()).thenReturn(1234L);

        var session =
                new Session("session-id", "client-session-id")
                        .addClientSessionAuthorisationRequest(
                                "client-session-id", Map.of("client_id", List.of("a-client-id")));

        sessionService.save(session);

        var serialisedSession =
                "{\"session_id\":\"session-id\",\"client_session_id\":\"client-session-id\",\"authentication_requests\":{\"client-session-id\":{\"client_id\":[\"a-client-id\"]}},\"state\":\"NEW\",\"email_address\":null,\"retry_count\":0}";
        verify(redis).saveWithExpiry("session-id", serialisedSession, 1234L);
    }

    @Test
    public void shouldRetrieveSessionUsingRequestHeaders() {
        var serialisedSession =
                "{\"session_id\":\"session-id\",\"client_session_id\":\"client-session-id\",\"authentication_requests\":{}},\"state\":\"NEW\",\"email_address\":null,\"retry_count\":0}";

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

        var session =
                sessionService.getSessionFromRequestHeaders(Map.of("Session-Id", "session-id"));

        assertTrue(session.isEmpty());
    }

    @Test
    void
            shouldReturnOptionalEmptyWhenGetSessionFromSessionCookieCalledWithIncorrectCookieHeaderValues() {
        assertEquals(Optional.empty(), sessionService.getSessionFromSessionCookie(Map.of()));
        assertEquals(
                Optional.empty(),
                sessionService.getSessionFromSessionCookie(
                        Map.ofEntries(Map.entry("header", "value"))));
        assertEquals(
                Optional.empty(),
                sessionService.getSessionFromSessionCookie(
                        Map.ofEntries(Map.entry(REQUEST_COOKIE_HEADER, ""))));
        assertEquals(
                Optional.empty(),
                sessionService.getSessionFromSessionCookie(
                        Map.ofEntries(Map.entry(REQUEST_COOKIE_HEADER, "gs=this is bad"))));
        assertEquals(
                Optional.empty(),
                sessionService.getSessionFromSessionCookie(
                        Map.ofEntries(Map.entry(REQUEST_COOKIE_HEADER, "gs=no-semi-colon.123"))));
        assertEquals(
                Optional.empty(),
                sessionService.getSessionFromSessionCookie(
                        Map.ofEntries(Map.entry(REQUEST_COOKIE_HEADER, "gs=no-dot;"))));
    }

    @Test
    void shouldReturnSessionFromSessionCookieCalledWithValidCookieHeaderValues() {
        String serialisedSession =
                "{\"session_id\":\"session-id\",\"client_session_id\":\"client-session-id\",\"authentication_requests\":{\"client-session-id\":{\"client_id\":[\"a-client-id\"]}},\"state\":\"NEW\",\"email_address\":null,\"retry_count\":0}";

        when(redis.keyExists("session-id")).thenReturn(true);
        when(redis.getValue("session-id")).thenReturn(serialisedSession);

        Optional<Session> session =
                sessionService.getSessionFromSessionCookie(
                        Map.ofEntries(Map.entry(REQUEST_COOKIE_HEADER, "gs=session-id.456;")));

        assertTrue(session.isPresent());
        assertEquals("session-id", session.get().getSessionId());
    }

    @Test
    void shouldNotReturnSessionFromSessionCookieCalledWithMissingSessionId() {
        when(redis.keyExists("session-id")).thenReturn(false);
        Optional<Session> session =
                sessionService.getSessionFromSessionCookie(
                        Map.ofEntries(Map.entry(REQUEST_COOKIE_HEADER, "gs=session-id.456;")));

        assertFalse(session.isPresent());
    }

    @Test
    void shouldUpdateSessionIdInRedisAndDeleteOldKey() {
        var session =
                new Session("session-id", "client-session-id")
                        .addClientSessionAuthorisationRequest(
                                "client-session-id", Map.of("client_id", List.of("a-client-id")));

        sessionService.save(session);
        sessionService.updateSessionId(session);

        verify(redis, times(2)).saveWithExpiry(anyString(), anyString(), anyLong());
        verify(redis).deleteValue("session-id");
    }
}
