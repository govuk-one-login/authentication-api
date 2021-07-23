package uk.gov.di.services;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.junit.jupiter.api.Test;
import uk.gov.di.entity.ClientSession;
import uk.gov.di.entity.Session;

import java.time.LocalDateTime;
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
    private final ObjectMapper objectMapper =
            JsonMapper.builder().addModule(new JavaTimeModule()).build();

    private final SessionService sessionService = new SessionService(configuration, redis);

    @Test
    public void shouldPersistSessionToRedisWithExpiry() throws JsonProcessingException {
        when(configuration.getSessionExpiry()).thenReturn(1234L);

        ClientSession clientSession =
                new ClientSession(Map.of("client_id", List.of("a-client-id")), LocalDateTime.now());
        var session =
                new Session("session-id", "client-session-id")
                        .setClientSession("client-session-id", clientSession);

        sessionService.save(session);

        verify(redis, times(1))
                .saveWithExpiry("session-id", objectMapper.writeValueAsString(session), 1234L);
    }

    @Test
    public void shouldRetrieveSessionUsingRequestHeaders() throws JsonProcessingException {
        when(redis.keyExists("session-id")).thenReturn(true);
        when(redis.getValue("session-id")).thenReturn(generateSearlizedSession());

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
    void shouldReturnSessionFromSessionCookieCalledWithValidCookieHeaderValues()
            throws JsonProcessingException {
        when(redis.keyExists("session-id")).thenReturn(true);
        when(redis.getValue("session-id")).thenReturn(generateSearlizedSession());

        Optional<Session> sessionFromSessionCookie =
                sessionService.getSessionFromSessionCookie(
                        Map.ofEntries(Map.entry(REQUEST_COOKIE_HEADER, "gs=session-id.456;")));

        assertTrue(sessionFromSessionCookie.isPresent());
        assertEquals("session-id", sessionFromSessionCookie.get().getSessionId());
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
                        .setClientSession(
                                "client-session-id",
                                new ClientSession(
                                        Map.of("client_id", List.of("a-client-id")),
                                        LocalDateTime.now()));

        sessionService.save(session);
        sessionService.updateSessionId(session);

        verify(redis, times(2)).saveWithExpiry(anyString(), anyString(), anyLong());
        verify(redis).deleteValue("session-id");
    }

    private String generateSearlizedSession() throws JsonProcessingException {
        ClientSession clientSession =
                new ClientSession(Map.of("client_id", List.of("a-client-id")), LocalDateTime.now());
        var session =
                new Session("session-id", "client-session-id")
                        .setClientSession("client-session-id", clientSession);

        return objectMapper.writeValueAsString(session);
    }
}
