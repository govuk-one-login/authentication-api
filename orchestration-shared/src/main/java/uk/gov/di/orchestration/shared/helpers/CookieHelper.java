package uk.gov.di.orchestration.shared.helpers;

import java.net.HttpCookie;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import static java.lang.String.format;
import static java.util.Collections.emptyList;
import static uk.gov.di.orchestration.shared.helpers.PersistentIdHelper.isOldPersistentSessionCookieWithoutTimestamp;
import static uk.gov.di.orchestration.shared.helpers.PersistentIdHelper.isValidPersistentSessionCookieWithDoubleDashedTimestamp;

public class CookieHelper {

    public static final String REQUEST_COOKIE_HEADER = "Cookie";
    public static final String RESPONSE_COOKIE_HEADER = "Set-Cookie";
    public static final String PERSISTENT_COOKIE_NAME = "di-persistent-session-id";
    public static final String SESSION_COOKIE_NAME = "gs";
    public static final String BROWSER_SESSION_COOKIE_NAME = "bsid";

    public static final String LANGUAGE_COOKIE_NAME = "lng";

    private CookieHelper() {}

    public static Optional<HttpCookie> getHttpCookieFromRequestHeaders(
            Map<String, String> headers, String cookieName) {
        return getHttpCookieFromHeaders(headers, cookieName, REQUEST_COOKIE_HEADER);
    }

    public static Optional<HttpCookie> getHttpCookieFromResponseHeaders(
            Map<String, String> headers, String cookieName) {
        return getHttpCookieFromHeaders(headers, cookieName, RESPONSE_COOKIE_HEADER);
    }

    public static Optional<HttpCookie> getHttpCookieFromMultiValueResponseHeaders(
            Map<String, List<String>> headers, String cookieName) {

        var cookieHeader =
                headers.containsKey(RESPONSE_COOKIE_HEADER)
                        ? headers.get(RESPONSE_COOKIE_HEADER)
                        : headers.getOrDefault(RESPONSE_COOKIE_HEADER.toLowerCase(), emptyList());

        return cookieHeader.stream()
                .map(CookieHelper::parseStringToHttpCookie)
                .flatMap(Optional::stream)
                .filter(cookie -> cookieName.equals(cookie.getName()))
                .findFirst();
    }

    public static Optional<HttpCookie> getHttpCookieFromHeaders(
            Map<String, String> headers, String cookieName, String headerName) {
        var cookieHeader = cookieHeader(headers, headerName);

        if (cookieHeader.isEmpty()) {
            return Optional.empty();
        }
        String cookies = headers.get(cookieHeader.get());

        String[] cookiesList = cookies.split(";");
        String cookie =
                Arrays.stream(cookiesList)
                        .filter(t -> t.trim().startsWith(cookieName + "="))
                        .findFirst()
                        .orElse(null);

        if (cookie == null) {
            return Optional.empty();
        }

        return parseStringToHttpCookie(cookie);
    }

    public static Optional<String> getSessionIdFromRequestHeaders(Map<String, String> headers) {
        return parseSessionCookie(headers).map(SessionCookieIds::getSessionId);
    }

    public static Optional<String> getClientSessionIdFromRequestHeaders(
            Map<String, String> headers) {
        return parseSessionCookie(headers).map(SessionCookieIds::getClientSessionId);
    }

    public static Optional<SessionCookieIds> parseSessionCookie(Map<String, String> headers) {
        Optional<HttpCookie> httpCookie =
                getHttpCookieFromRequestHeaders(headers, SESSION_COOKIE_NAME);
        if (httpCookie.isEmpty()) {
            return Optional.empty();
        }

        String[] cookieValues = httpCookie.get().getValue().split("\\.");
        if (cookieValues.length != 2) {
            return Optional.empty();
        }
        final String sid = cookieValues[0];
        final String csid = cookieValues[1];

        return Optional.of(
                new SessionCookieIds() {
                    public String getSessionId() {
                        return sid;
                    }

                    public String getClientSessionId() {
                        return csid;
                    }
                });
    }

    public static Optional<String> parseBrowserSessionCookie(Map<String, String> headers) {
        Optional<HttpCookie> httpCookie =
                getHttpCookieFromRequestHeaders(headers, BROWSER_SESSION_COOKIE_NAME);
        if (httpCookie.isEmpty()) {
            return Optional.empty();
        }

        String cookieValues = httpCookie.get().getValue();

        return Optional.of(cookieValues);
    }

    public static Optional<String> parsePersistentCookie(Map<String, String> headers) {
        Optional<HttpCookie> httpCookie =
                getHttpCookieFromRequestHeaders(headers, PERSISTENT_COOKIE_NAME);
        if (httpCookie.isEmpty()) {
            return Optional.empty();
        }

        String[] cookieValues = httpCookie.get().getValue().split("\\.");
        if (cookieValues.length != 1) {
            return Optional.empty();
        }
        final String persistentId = cookieValues[0];

        // Temporary measure, as commit 75a10df4376397d5a454b87b5cee689e13a71e20 introduced a bug
        // whereby persistent session ID could end up as --<timestamp>--<timestamp>. In these cases
        // we should just generate a new one to get back on track. It will be possible to remove
        // this 18 months after it is first merged(== the expiry time of that cookie at the point of
        // issue in November 2023) i.e. 26/05/2025
        if (isValidPersistentSessionCookieWithDoubleDashedTimestamp(persistentId)) {
            return Optional.of(persistentId);
        }

        if (isOldPersistentSessionCookieWithoutTimestamp(persistentId)) {
            return Optional.of(appendTimestampToCookieValue(persistentId));
        }

        return Optional.empty();
    }

    private static Optional<HttpCookie> parseStringToHttpCookie(String cookie) {
        HttpCookie httpCookie;
        try {
            httpCookie = HttpCookie.parse(cookie).stream().findFirst().orElse(null);
        } catch (IllegalArgumentException e) {
            return Optional.empty();
        }
        if (httpCookie == null) {
            return Optional.empty();
        }
        return Optional.of(httpCookie);
    }

    private static Optional<String> cookieHeader(Map<String, String> headers, String headerName) {
        if (headers == null) {
            return Optional.empty();
        }

        return Stream.of(headerName, headerName.toLowerCase())
                .filter(headers.keySet()::contains)
                .findFirst();
    }

    public interface SessionCookieIds {
        String getSessionId();

        String getClientSessionId();
    }

    public static String buildCookieString(
            String cookieName,
            String cookieValue,
            Integer maxAge,
            String attributes,
            String domain) {
        return format(
                "%s=%s; Max-Age=%d; Domain=%s; %s",
                cookieName, cookieValue, maxAge, domain, attributes);
    }

    public static String buildCookieString(
            String cookieName, String cookieValue, String attributes, String domain) {
        return format("%s=%s; Domain=%s; %s", cookieName, cookieValue, domain, attributes);
    }

    public static String appendTimestampToCookieValue(String cookieValue) {
        return cookieValue + "--" + NowHelper.now().getTime();
    }
}
