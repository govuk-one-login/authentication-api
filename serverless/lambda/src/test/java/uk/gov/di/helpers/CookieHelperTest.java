package uk.gov.di.helpers;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.net.HttpCookie;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static uk.gov.di.helpers.CookieHelper.REQUEST_COOKIE_HEADER;
import static uk.gov.di.helpers.CookieHelper.SessionCookieIds;

public class CookieHelperTest {

    static Stream<String> inputs() {
        return Stream.of(REQUEST_COOKIE_HEADER);
    }

    @ParameterizedTest(name = "with header {0}")
    @MethodSource("inputs")
    void shouldReturnIdsFromValidCookieStringWithMultipleCookeies(String header) {
        String cookieString = "Version=1; gs=session-id.456;name=ts";
        Map<String, String> headers = Map.ofEntries(Map.entry(header, cookieString.toString()));

        Optional<SessionCookieIds> ids = CookieHelper.parseSessionCookie(headers);

        assertEquals("session-id", ids.get().getSessionId());
        assertEquals("456", ids.get().getClientSessionId());
    }

    @ParameterizedTest(name = "with header {0}")
    @MethodSource("inputs")
    void shouldReturnIdsFromValidCookie(String header) {
        HttpCookie cookie = new HttpCookie("gs", "session-id.456");
        Map<String, String> headers = Map.ofEntries(Map.entry(header, cookie.toString()));

        Optional<SessionCookieIds> ids = CookieHelper.parseSessionCookie(headers);

        assertEquals("session-id", ids.get().getSessionId());
        assertEquals("456", ids.get().getClientSessionId());
    }

    @ParameterizedTest(name = "with header {0}")
    @MethodSource("inputs")
    void shouldReturnEmptyIfCookieMalformatted(String header) {
        assertEquals(
                Optional.empty(),
                CookieHelper.parseSessionCookie(
                        Map.ofEntries(Map.entry(header, "someinvalidvalue"))));

        assertEquals(Optional.empty(), CookieHelper.parseSessionCookie(Map.of()));

        assertEquals(
                Optional.empty(),
                CookieHelper.parseSessionCookie(Map.ofEntries(Map.entry("header", "value"))));
        assertEquals(
                Optional.empty(),
                CookieHelper.parseSessionCookie(Map.ofEntries(Map.entry(header, ""))));
        assertEquals(
                Optional.empty(),
                CookieHelper.parseSessionCookie(
                        Map.ofEntries(Map.entry(header, "gs=this is bad"))));
        assertEquals(
                Optional.empty(),
                CookieHelper.parseSessionCookie(Map.ofEntries(Map.entry(header, "gs=no-dot;"))));
        assertEquals(
                Optional.empty(),
                CookieHelper.parseSessionCookie(
                        Map.ofEntries(Map.entry(header, "gs=one-value.two-value.three-value;"))));
        assertEquals(
                Optional.empty(),
                CookieHelper.parseSessionCookie(
                        Map.ofEntries(Map.entry(header, "gsdsds=one-value.two-value"))));
    }
}
