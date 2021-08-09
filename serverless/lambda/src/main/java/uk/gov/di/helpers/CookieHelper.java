package uk.gov.di.helpers;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.HttpCookie;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static java.lang.String.format;

public class CookieHelper {

    private static final Logger LOGGER = LoggerFactory.getLogger(CookieHelper.class);

    public static final String REQUEST_COOKIE_HEADER = "Cookie";
    private static final String SESSION_ID = "a-session-id";

    public static Optional<SessionCookieIds> parseSessionCookie(Map<String, String> headers) {
        var cookieHeader = cookieHeader(headers);

        if (cookieHeader.isEmpty()) {
            return Optional.empty();
        }
        String cookies = headers.get(cookieHeader.get());

        LOGGER.debug("Session Cookie: {}", cookies);

        String[] cookiesList = cookies.split(";");
        String cookie =
                Arrays.stream(cookiesList)
                        .filter(t -> t.trim().startsWith("gs="))
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

        String[] cookieValues = httpCookie.getValue().split("\\.");
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

        return List.of(REQUEST_COOKIE_HEADER, REQUEST_COOKIE_HEADER.toLowerCase()).stream()
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
                "gs", SESSION_ID, clientSessionId, 1800, "Secure; HttpOnly;");
    }
}
