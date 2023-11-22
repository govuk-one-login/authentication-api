package uk.gov.di.authentication.shared.helpers;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.net.HttpCookie;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.authentication.shared.helpers.CookieHelper.PERSISTENT_COOKIE_NAME;
import static uk.gov.di.authentication.shared.helpers.CookieHelper.REQUEST_COOKIE_HEADER;
import static uk.gov.di.authentication.shared.helpers.CookieHelper.RESPONSE_COOKIE_HEADER;
import static uk.gov.di.authentication.shared.helpers.CookieHelper.getHttpCookieFromMultiValueResponseHeaders;
import static uk.gov.di.authentication.shared.helpers.CookieHelper.getHttpCookieFromResponseHeaders;
import static uk.gov.di.authentication.shared.helpers.CookieHelper.parsePersistentCookie;

public class CookieHelperTest {
    private static final CookieHelper cookieHelper = new CookieHelper();

    static Stream<String> inputs() {
        return Stream.of(REQUEST_COOKIE_HEADER, REQUEST_COOKIE_HEADER.toLowerCase());
    }

    static Stream<String> responseInputs() {
        return Stream.of(RESPONSE_COOKIE_HEADER, RESPONSE_COOKIE_HEADER.toLowerCase());
    }

    private static final String ARBITRARY_UNIX_TIMESTAMP = "1700558480962";
    private static final String PERSISTENT_SESSION_ID_COOKIE_VALUE =
            IdGenerator.generate() + "--" + ARBITRARY_UNIX_TIMESTAMP;

    @ParameterizedTest(name = "with header {0}")
    @MethodSource("inputs")
    void shouldReturnIdsFromValidSessionCookieStringWithMultipleCookies(String header) {
        String cookieString =
                "Version=1; gs=session-id.456;cookies_preferences_set={\"analytics\":true};name=ts";
        Map<String, String> headers = Map.ofEntries(Map.entry(header, cookieString));

        CookieHelper.SessionCookieIds ids = cookieHelper.parseSessionCookie(headers).orElseThrow();

        assertEquals("session-id", ids.getSessionId());
        assertEquals("456", ids.getClientSessionId());
    }

    @ParameterizedTest(name = "with header {0}")
    @MethodSource("inputs")
    void shouldReturnIdsFromValidPersistentCookieStringWithMultipleCookies(String header) {
        String cookieString =
                String.format(
                        "Version=1; di-persistent-session-id=%s;gs=session-id.456;cookies_preferences_set={\"analytics\":true};name=ts",
                        PERSISTENT_SESSION_ID_COOKIE_VALUE);
        Map<String, String> headers = Map.ofEntries(Map.entry(header, cookieString));

        String id = parsePersistentCookie(headers).orElseThrow();

        assertEquals(PERSISTENT_SESSION_ID_COOKIE_VALUE, id);
    }

    @ParameterizedTest(name = "with header {0}")
    @MethodSource("inputs")
    void shouldReturnIdsFromValidSessionCookie(String header) {
        HttpCookie cookie = new HttpCookie("gs", "session-id.456");
        Map<String, String> headers = Map.ofEntries(Map.entry(header, cookie.toString()));

        CookieHelper.SessionCookieIds ids = cookieHelper.parseSessionCookie(headers).orElseThrow();

        assertEquals("session-id", ids.getSessionId());
        assertEquals("456", ids.getClientSessionId());
    }

    @ParameterizedTest(name = "with header {0}")
    @MethodSource("inputs")
    void shouldReturnIdsFromValidPersistentCookie(String header) {
        HttpCookie cookie =
                new HttpCookie("di-persistent-session-id", PERSISTENT_SESSION_ID_COOKIE_VALUE);
        Map<String, String> headers = Map.ofEntries(Map.entry(header, cookie.toString()));

        String id = parsePersistentCookie(headers).orElseThrow();

        assertEquals(PERSISTENT_SESSION_ID_COOKIE_VALUE, id);
    }

    @Test
    void shouldNotReturnIdFromInvalidPersistentCookie() {
        String existingPersistentSessionId = "--1700558480962--1700558480963";
        HttpCookie cookie = new HttpCookie("di-persistent-session-id", existingPersistentSessionId);
        Map<String, String> headers =
                Map.ofEntries(Map.entry(REQUEST_COOKIE_HEADER, cookie.toString()));

        Optional<String> id = parsePersistentCookie(headers);

        assertEmpty(id);
    }

    @Test
    void shouldAppendTimestampToPersistentCookieWhenMissing() {
        String existingPersistentSessionId = IdGenerator.generate();
        HttpCookie cookie = new HttpCookie("di-persistent-session-id", existingPersistentSessionId);
        Map<String, String> headers =
                Map.ofEntries(Map.entry(REQUEST_COOKIE_HEADER, cookie.toString()));

        Optional<String> id = parsePersistentCookie(headers);

        assertTrue(id.get().startsWith(existingPersistentSessionId));
        assertTrue(
                PersistentIdHelper.isValidPersistentSessionCookieWithDoubleDashedTimestamp(
                        id.get()));
    }

    @ParameterizedTest(name = "with header {0}")
    @MethodSource("inputs")
    void shouldReturnEmptyIfSessionCookieNotPresent(String header) {
        assertEmpty(cookieHelper.parseSessionCookie(null));
        assertEmpty(cookieHelper.parseSessionCookie(Map.of()));
        assertEmpty(cookieHelper.parseSessionCookie(Map.of(header, "value")));
    }

    @ParameterizedTest(name = "with header {0}")
    @MethodSource("inputs")
    void shouldReturnEmptyIfCookieMalformatted(String header) {
        assertEmpty(cookieHelper.parseSessionCookie(Map.of(header, "")));
        assertEmpty(cookieHelper.parseSessionCookie(Map.of(header, "someinvalidvalue")));
        assertEmpty(cookieHelper.parseSessionCookie(Map.of(header, "gs=this is bad")));
        assertEmpty(cookieHelper.parseSessionCookie(Map.of(header, "gs=no-dot")));
        assertEmpty(
                cookieHelper.parseSessionCookie(
                        Map.of(header, "gs=one-value.two-value.three-value;")));
        assertEmpty(cookieHelper.parseSessionCookie(Map.of(header, "gsdsds=one-value.two-value")));
    }

    @ParameterizedTest(name = "with header {0}")
    @MethodSource("inputs")
    void shouldReturnEmptyIPersistentCookieMalformatted(String header) {
        assertEmpty(parsePersistentCookie(Map.of(header, "")));
        assertEmpty(parsePersistentCookie(Map.of(header, "someinvalidvalue")));
        assertEmpty(
                parsePersistentCookie(Map.of(header, "di-persistent-session-id=dot.fsfdfsfd;")));
        assertEmpty(
                parsePersistentCookie(
                        Map.of(
                                header,
                                "di-persistent-session-id=one-value.two-value.three-value;")));
        assertEmpty(
                parsePersistentCookie(
                        Map.of(header, "di-persistent-session-idfds=one-value.two-value\"")));
    }

    @ParameterizedTest(name = "with header {0}")
    @MethodSource("inputs")
    void shouldReturnCookiePrefsFromValidSessionCookieStringWithMultipleCookies(String header) {
        String cookieString =
                "Version=1; gs=session-id.456;cookies_preferences_set={\"analytics\":false};name=ts";
        Map<String, String> headers = Map.ofEntries(Map.entry(header, cookieString));

        HttpCookie cookie =
                CookieHelper.getHttpCookieFromRequestHeaders(headers, "cookies_preferences_set")
                        .orElseThrow();

        assertThat(cookie.getValue(), containsString("\"analytics\":false"));
    }

    @ParameterizedTest(name = "with header {0}")
    @MethodSource("inputs")
    void shouldReturnEmptyCookiePrefsIfCookieNotPresent(String header) {
        assertEmpty(getHttpCookieFromResponseHeaders(null, "cookies_preferences_set"));
        assertEmpty(
                CookieHelper.getHttpCookieFromRequestHeaders(Map.of(), "cookies_preferences_set"));
        assertEmpty(
                CookieHelper.getHttpCookieFromRequestHeaders(
                        Map.of(header, "value"), "cookies_preferences_set"));
    }

    @ParameterizedTest(name = "with header {0}")
    @MethodSource("responseInputs")
    void shouldReturnIdsFromPersistentCookieStringWithMultipleValuesMap(String header) {
        Map<String, List<String>> cookieMap = new HashMap<>();
        String persistentCookie = "di-persistent-session-id=" + PERSISTENT_SESSION_ID_COOKIE_VALUE;
        String sessionCookie = "gs=session-id.456";
        cookieMap.put(header, List.of(persistentCookie, sessionCookie));

        HttpCookie httpCookie =
                getHttpCookieFromMultiValueResponseHeaders(cookieMap, PERSISTENT_COOKIE_NAME)
                        .orElseThrow();

        assertEquals(PERSISTENT_SESSION_ID_COOKIE_VALUE, httpCookie.getValue());
    }

    @ParameterizedTest(name = "with header {0}")
    @MethodSource("responseInputs")
    void shouldReturnCookiePrefsFromValidResponseCookieStringWithMultipleCookies(String header) {
        String cookieString =
                "Version=1; gs=session-id.456;cookies_preferences_set={\"analytics\":false};name=ts";
        Map<String, String> headers = Map.ofEntries(Map.entry(header, cookieString));

        HttpCookie cookie =
                getHttpCookieFromResponseHeaders(headers, "cookies_preferences_set").orElseThrow();

        assertThat(cookie.getValue(), containsString("\"analytics\":false"));
    }

    @ParameterizedTest(name = "with header {0}")
    @MethodSource("responseInputs")
    void shouldReturnEmptyCookiePrefsIfResponseCookieNotPresent(String header) {
        assertEmpty(getHttpCookieFromResponseHeaders(null, "cookies_preferences_set"));
        assertEmpty(getHttpCookieFromResponseHeaders(Map.of(), "cookies_preferences_set"));
        assertEmpty(
                getHttpCookieFromResponseHeaders(
                        Map.of("header", "value"), "cookies_preferences_set"));
    }

    private static void assertEmpty(Object input) {
        assertEquals(Optional.empty(), input);
    }
}
