package uk.gov.di.authentication.shared.services;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.helpers.CookieHelper;

import java.util.Collections;
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

class SessionServiceTest {

    private final RedisConnectionService redis = mock(RedisConnectionService.class);
    private final ConfigurationService configuration = mock(ConfigurationService.class);
    private final ObjectMapper objectMapper =
            JsonMapper.builder().addModule(new JavaTimeModule()).build();

    private final SessionService sessionService = new SessionService(configuration, redis);

    @Test
    void shouldPersistSessionToRedisWithExpiry() throws JsonProcessingException {
        when(configuration.getSessionExpiry()).thenReturn(1234L);

        var session = new Session("session-id").addClientSession("client-session-id");

        sessionService.save(session);

        verify(redis, times(1))
                .saveWithExpiry("session-id", objectMapper.writeValueAsString(session), 1234L);
    }

    @Test
    void shouldRetrieveSessionUsingRequestHeaders() throws JsonProcessingException {
        when(redis.keyExists("session-id")).thenReturn(true);
        when(redis.getValue("session-id")).thenReturn(generateSearlizedSession());

        var sessionInRedis =
                sessionService.getSessionFromRequestHeaders(Map.of("Session-Id", "session-id"));

        sessionInRedis.ifPresentOrElse(
                session -> assertThat(session.getSessionId(), is("session-id")),
                () -> fail("Could not retrieve result"));
    }

    @Test
    void shouldNotRetrieveSessionForLowerCaseHeaderName() throws JsonProcessingException {
        when(redis.keyExists("session-id")).thenReturn(true);
        when(redis.getValue("session-id")).thenReturn(generateSearlizedSession());

        var sessionInRedis =
                sessionService.getSessionFromRequestHeaders(Map.of("session-id", "session-id"));
        assertTrue(sessionInRedis.isEmpty());
    }

    @Test
    void shouldNotRetrieveSessionWithNoHeaders() {
        var session = sessionService.getSessionFromRequestHeaders(Collections.emptyMap());
        assertTrue(session.isEmpty());
    }

    @Test
    void shouldNotRetrieveSessionWithNullHeaders() {
        var session = sessionService.getSessionFromRequestHeaders(null);
        assertTrue(session.isEmpty());
    }

    @Test
    void shouldNotRetrieveSessionWithMissingHeader() {
        var session = sessionService.getSessionFromRequestHeaders(Map.of("Something", "Else"));
        assertTrue(session.isEmpty());
    }

    @Test
    void shouldNotRetrieveSessionIfNotPresentInRedis() {
        when(redis.keyExists("session-id")).thenReturn(false);

        var session =
                sessionService.getSessionFromRequestHeaders(Map.of("Session-Id", "session-id"));

        assertTrue(session.isEmpty());
    }

    @Test
    void
            shouldReturnOptionalEmptyWhenGetSessionFromSessionCookieCalledWithIncorrectCookieHeaderValues() {
        assertEquals(
                Optional.empty(),
                sessionService.getSessionFromSessionCookie(
                        Map.ofEntries(
                                Map.entry(CookieHelper.REQUEST_COOKIE_HEADER, "gs=this is bad"))));
    }

    @Test
    void shouldReturnSessionFromSessionCookieCalledWithValidCookieHeaderValues()
            throws JsonProcessingException {
        when(redis.keyExists("session-id")).thenReturn(true);
        when(redis.getValue("session-id")).thenReturn(generateSearlizedSession());

        Optional<Session> sessionFromSessionCookie =
                sessionService.getSessionFromSessionCookie(
                        Map.ofEntries(
                                Map.entry(
                                        CookieHelper.REQUEST_COOKIE_HEADER, "gs=session-id.456;")));

        assertTrue(sessionFromSessionCookie.isPresent());
        Assertions.assertEquals("session-id", sessionFromSessionCookie.get().getSessionId());
    }

    @Test
    void shouldNotReturnSessionFromSessionCookieCalledWithMissingSessionId() {
        when(redis.keyExists("session-id")).thenReturn(false);
        Optional<Session> session =
                sessionService.getSessionFromSessionCookie(
                        Map.ofEntries(
                                Map.entry(
                                        CookieHelper.REQUEST_COOKIE_HEADER, "gs=session-id.456;")));

        assertFalse(session.isPresent());
    }

    @Test
    void shouldUpdateSessionIdInRedisAndDeleteOldKey() {
        var session = new Session("session-id").addClientSession("client-session-id");

        sessionService.save(session);
        sessionService.updateSessionId(session);

        verify(redis, times(2)).saveWithExpiry(anyString(), anyString(), anyLong());
        verify(redis).deleteValue("session-id");
    }

    @Test
    void shouldDeleteSessionIdFromRedis() {
        var session = new Session("session-id").addClientSession("client-session-id");

        sessionService.save(session);
        sessionService.deleteSessionFromRedis(session.getSessionId());

        verify(redis).deleteValue("session-id");
    }

    private String generateSearlizedSession() throws JsonProcessingException {
        var session = new Session("session-id").addClientSession("client-session-id");

        return objectMapper.writeValueAsString(session);
    }
}
