package uk.gov.di.authentication.shared.helpers;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.net.HttpCookie;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static uk.gov.di.authentication.shared.helpers.CookieHelper.REQUEST_COOKIE_HEADER;
import static uk.gov.di.authentication.shared.helpers.CookieHelper.SessionCookieIds;
import static uk.gov.di.authentication.shared.helpers.CookieHelper.parseSessionCookie;

public class CookieHelperTest {

    static Stream<String> inputs() {
        return Stream.of(REQUEST_COOKIE_HEADER, REQUEST_COOKIE_HEADER.toLowerCase());
    }

    @ParameterizedTest(name = "with header {0}")
    @MethodSource("inputs")
    void shouldReturnIdsFromValidCookieStringWithMultipleCookeies(String header) {
        String cookieString = "Version=1; gs=session-id.456;name=ts";
        Map<String, String> headers = Map.ofEntries(Map.entry(header, cookieString.toString()));

        SessionCookieIds ids = parseSessionCookie(headers).orElseThrow();

        assertEquals("session-id", ids.getSessionId());
        assertEquals("456", ids.getClientSessionId());
    }

    @ParameterizedTest(name = "with header {0}")
    @MethodSource("inputs")
    void shouldReturnIdsFromValidCookie(String header) {
        HttpCookie cookie = new HttpCookie("gs", "session-id.456");
        Map<String, String> headers = Map.ofEntries(Map.entry(header, cookie.toString()));

        SessionCookieIds ids = parseSessionCookie(headers).orElseThrow();

        assertEquals("session-id", ids.getSessionId());
        assertEquals("456", ids.getClientSessionId());
    }

    @ParameterizedTest(name = "with header {0}")
    @MethodSource("inputs")
    void shouldReturnEmptyIfCookieNotPresent(String header) {
        assertEmpty(parseSessionCookie(null));
        assertEmpty(parseSessionCookie(Map.of()));
        assertEmpty(parseSessionCookie(Map.of("header", "value")));
    }

    @ParameterizedTest(name = "with header {0}")
    @MethodSource("inputs")
    void shouldReturnEmptyIfCookieMalformatted(String header) {
        assertEmpty(parseSessionCookie(Map.of(header, "")));
        assertEmpty(parseSessionCookie(Map.of(header, "someinvalidvalue")));
        assertEmpty(parseSessionCookie(Map.of(header, "gs=this is bad")));
        assertEmpty(parseSessionCookie(Map.of(header, "gs=no-dot;")));
        assertEmpty(parseSessionCookie(Map.of(header, "gs=one-value.two-value.three-value;")));
        assertEmpty(parseSessionCookie(Map.of(header, "gsdsds=one-value.two-value")));
    }

    private static void assertEmpty(Object input) {
        assertEquals(Optional.empty(), input);
    }
}
