package uk.gov.di.authentication.shared.services;

import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.helpers.CookieHelper;
import uk.gov.di.authentication.shared.serialization.Json;

import java.util.Collections;
import java.util.Map;
import java.util.Optional;

import static java.lang.String.format;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class SessionServiceTest {
    private static final String SESSION_ID = "test-session-id";
    private final RedisConnectionService redis = mock(RedisConnectionService.class);
    private final ConfigurationService configuration = mock(ConfigurationService.class);
    private final Json objectMapper = SerializationService.getInstance();

    private final SessionService sessionService = new SessionService(configuration, redis);

    @Test
    void shouldRetrieveSessionUsingRequestHeaders() throws Json.JsonException {
        var serialisedSession = generateSearlizedSession();
        when(redis.keyExists(SESSION_ID)).thenReturn(true);
        when(redis.getValue(SESSION_ID)).thenReturn(serialisedSession);

        var sessionInRedis =
                sessionService.getSessionFromRequestHeaders(Map.of("Session-Id", SESSION_ID));

        if (sessionInRedis.isPresent()) {
            assertThat(
                    objectMapper.writeValueAsString(sessionInRedis.get()), is(serialisedSession));
        } else {
            fail("Could not retrieve result");
        }
    }

    @Test
    void shouldNotRetrieveSessionForLowerCaseHeaderName() throws Json.JsonException {
        when(redis.keyExists(SESSION_ID)).thenReturn(true);
        when(redis.getValue(SESSION_ID)).thenReturn(generateSearlizedSession());

        var sessionInRedis =
                sessionService.getSessionFromRequestHeaders(Map.of("session-id", SESSION_ID));
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
        when(redis.keyExists(SESSION_ID)).thenReturn(false);

        var session = sessionService.getSessionFromRequestHeaders(Map.of("Session-Id", SESSION_ID));

        assertTrue(session.isEmpty());
    }

    @Test
    void
            shouldReturnOptionalEmptyWhenGetSessionFromSessionCookieCalledWithIncorrectCookieHeaderValues() {
        assertEquals(
                Optional.empty(),
                sessionService.getSessionFromSessionCookie(
                        Map.of(CookieHelper.REQUEST_COOKIE_HEADER, "gs=this is bad")));
    }

    @Test
    void shouldReturnSessionFromSessionCookieCalledWithValidCookieHeaderValues()
            throws Json.JsonException {
        var serialisedSession = generateSearlizedSession();
        when(redis.keyExists(SESSION_ID)).thenReturn(true);
        when(redis.getValue(SESSION_ID)).thenReturn(serialisedSession);

        Optional<Session> sessionFromSessionCookie =
                sessionService.getSessionFromSessionCookie(
                        Map.of(
                                CookieHelper.REQUEST_COOKIE_HEADER,
                                format("gs=%s.456;", SESSION_ID)));

        if (sessionFromSessionCookie.isPresent()) {
            assertThat(
                    objectMapper.writeValueAsString(sessionFromSessionCookie.get()),
                    is(serialisedSession));
        } else {
            fail("Could not retrieve result");
        }
    }

    @Test
    void shouldNotReturnSessionFromSessionCookieCalledWithMissingSessionId() {
        when(redis.keyExists(SESSION_ID)).thenReturn(false);
        Optional<Session> session =
                sessionService.getSessionFromSessionCookie(
                        Map.of(CookieHelper.REQUEST_COOKIE_HEADER, "gs=session-id.456;"));

        assertFalse(session.isPresent());
    }

    private String generateSearlizedSession() throws Json.JsonException {
        var session = new Session();

        return objectMapper.writeValueAsString(session);
    }
}
