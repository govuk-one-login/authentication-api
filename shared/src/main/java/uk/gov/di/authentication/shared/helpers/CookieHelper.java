package uk.gov.di.authentication.shared.helpers;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.HttpCookie;
import java.util.Arrays;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import static java.lang.String.format;

public class CookieHelper {

    private static final Logger LOGGER = LoggerFactory.getLogger(CookieHelper.class);

    public static final String REQUEST_COOKIE_HEADER = "Cookie";
    private static final String SESSION_ID = "a-session-id";

    public static Optional<HttpCookie> getHttpCookieFromHeaders(
            Map<String, String> headers, String cookieName) {
        var cookieHeader = cookieHeader(headers);

        if (cookieHeader.isEmpty()) {
            return Optional.empty();
        }
        String cookies = headers.get(cookieHeader.get());

        LOGGER.debug("Cookies: {}", cookies);

        String[] cookiesList = cookies.split(";");
        String cookie =
                Arrays.stream(cookiesList)
                        .filter(t -> t.trim().startsWith(cookieName + "="))
                        .findFirst()
                        .orElse(null);

        if (cookie == null) {
            return Optional.empty();
        }

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

    public static Optional<SessionCookieIds> parseSessionCookie(Map<String, String> headers) {
        Optional<HttpCookie> httpCookie = getHttpCookieFromHeaders(headers, "gs");
        if (!httpCookie.isPresent()) {
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

    private static Optional<String> cookieHeader(Map<String, String> headers) {
        if (headers == null) {
            return Optional.empty();
        }

        return Stream.of(REQUEST_COOKIE_HEADER, REQUEST_COOKIE_HEADER.toLowerCase())
                .filter(headers.keySet()::contains)
                .findFirst();
    }

    public interface SessionCookieIds {
        String getSessionId();

        String getClientSessionId();
    }

    public static String buildCookieString(String clientSessionId) {
        return format(
                "%s=%s.%s; Max-Age=%d; %s",
                "gs", SESSION_ID, clientSessionId, 3600, "Secure; HttpOnly;");
    }
}
