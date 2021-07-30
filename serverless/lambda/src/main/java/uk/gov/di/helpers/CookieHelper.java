package uk.gov.di.helpers;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.HttpCookie;
import java.util.Arrays;
import java.util.Map;
import java.util.Optional;

public class CookieHelper {

    private static final Logger LOGGER = LoggerFactory.getLogger(CookieHelper.class);

    public static final String REQUEST_COOKIE_HEADER = "cookie";

    public static Optional<SessionCookieIds> parseSessionCookie(Map<String, String> headers) {
        if (headers == null
                || !headers.containsKey(REQUEST_COOKIE_HEADER)
                || headers.get(REQUEST_COOKIE_HEADER).isEmpty()) {
            return Optional.empty();
        }
        String cookies = headers.get(REQUEST_COOKIE_HEADER);

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

    public interface SessionCookieIds {
        String getSessionId();

        String getClientSessionId();
    }
}
