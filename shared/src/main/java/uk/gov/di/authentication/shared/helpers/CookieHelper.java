package uk.gov.di.authentication.shared.helpers;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.net.HttpCookie;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import static java.lang.String.format;

public class CookieHelper {

    private static final Logger LOG = LogManager.getLogger(CookieHelper.class);

    public static final String REQUEST_COOKIE_HEADER = "Cookie";
    public static final String RESPONSE_COOKIE_HEADER = "Set-Cookie";
    public static final String PERSISTENT_COOKIE_NAME = "di-persistent-session-id";
    public static final String SESSION_COOKIE_NAME = "gs";

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
        String cookie =
                Stream.of(RESPONSE_COOKIE_HEADER, RESPONSE_COOKIE_HEADER.toLowerCase())
                        .filter(headers.keySet()::contains)
                        .findFirst()
                        .orElse(null);
        if (cookie == null) {
            return Optional.empty();
        }
        return headers.get(cookie).stream()
                .filter(
                        t ->
                                getHttpCookieFromHeaders(
                                                Map.of(RESPONSE_COOKIE_HEADER, t),
                                                cookieName,
                                                RESPONSE_COOKIE_HEADER)
                                        .isPresent())
                .map(CookieHelper::parseStringToHttpCookie)
                .findFirst()
                .orElse(Optional.empty());
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

        return Optional.of(persistentId);
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
}
