package uk.gov.di.helpers;

import org.junit.jupiter.api.Test;

import java.net.HttpCookie;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static uk.gov.di.helpers.CookieHelper.REQUEST_COOKIE_HEADER;
import static uk.gov.di.helpers.CookieHelper.SessionCookieIds;

public class CookieHelperTest {

    @Test
    void shouldReturnIdsFromValidCookieStringWithMultipleCookeies() {
        String cookieString = "Version=1; gs=session-id.456;name=ts";
        Map<String, String> headers =
                Map.ofEntries(Map.entry(REQUEST_COOKIE_HEADER, cookieString.toString()));

        Optional<SessionCookieIds> ids = CookieHelper.parseSessionCookie(headers);

        assertEquals("session-id", ids.get().getSessionId());
        assertEquals("456", ids.get().getClientSessionId());
    }

    @Test
    void shouldReturnIdsFromValidCookie() {
        HttpCookie cookie = new HttpCookie("gs", "session-id.456");
        Map<String, String> headers =
                Map.ofEntries(Map.entry(REQUEST_COOKIE_HEADER, cookie.toString()));

        Optional<SessionCookieIds> ids = CookieHelper.parseSessionCookie(headers);

        assertEquals("session-id", ids.get().getSessionId());
        assertEquals("456", ids.get().getClientSessionId());
    }

    @Test
    void shouldReturnEmptyIfCookieMalformatted() {
        assertEquals(
                Optional.empty(),
                CookieHelper.parseSessionCookie(
                        Map.ofEntries(Map.entry(REQUEST_COOKIE_HEADER, "someinvalidvalue"))));

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
                        Map.ofEntries(Map.entry(REQUEST_COOKIE_HEADER, "gs=no-dot;"))));
        assertEquals(
                Optional.empty(),
                CookieHelper.parseSessionCookie(
                        Map.ofEntries(
                                Map.entry(
                                        REQUEST_COOKIE_HEADER,
                                        "gs=one-value.two-value.three-value;"))));
        assertEquals(
                Optional.empty(),
                CookieHelper.parseSessionCookie(
                        Map.ofEntries(
                                Map.entry(REQUEST_COOKIE_HEADER, "gsdsds=one-value.two-value"))));
    }
}
