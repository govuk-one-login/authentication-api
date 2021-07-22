package uk.gov.di.helpers;

import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static uk.gov.di.helpers.CookieHelper.REQUEST_COOKIE_HEADER;
import static uk.gov.di.helpers.CookieHelper.SessionCookieIds;

public class CookieHelperTest {

    @Test
    void shouldReturnIdsFromValidCookie() {
        Map<String, String> headers =
                Map.ofEntries(Map.entry(REQUEST_COOKIE_HEADER, "gs=session-id.456;"));

        Optional<SessionCookieIds> ids = CookieHelper.parseSessionCookie(headers);

        assertEquals("session-id", ids.get().getSessionId());
        assertEquals("456", ids.get().getClientSessionId());
    }

    @Test
    void shouldReturnEmptyIfCookieMalformatted() {
        assertEquals(Optional.empty(), CookieHelper.parseSessionCookie(Map.of()));

        assertEquals(
                Optional.empty(),
                CookieHelper.parseSessionCookie(Map.ofEntries(Map.entry("header", "value"))));
        assertEquals(
                Optional.empty(),
                CookieHelper.parseSessionCookie(
                        Map.ofEntries(Map.entry(REQUEST_COOKIE_HEADER, ""))));
        assertEquals(
                Optional.empty(),
                CookieHelper.parseSessionCookie(
                        Map.ofEntries(Map.entry(REQUEST_COOKIE_HEADER, "gs=this is bad"))));
        assertEquals(
                Optional.empty(),
                CookieHelper.parseSessionCookie(
                        Map.ofEntries(Map.entry(REQUEST_COOKIE_HEADER, "gs=no-semi-colon.123"))));
        assertEquals(
                Optional.empty(),
                CookieHelper.parseSessionCookie(
                        Map.ofEntries(Map.entry(REQUEST_COOKIE_HEADER, "gs=no-dot;"))));
    }
}
