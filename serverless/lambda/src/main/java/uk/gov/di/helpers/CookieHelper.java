package uk.gov.di.helpers;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class CookieHelper {

    private static final Logger LOGGER = LoggerFactory.getLogger(CookieHelper.class);

    public static final String REQUEST_COOKIE_HEADER = "Cookie";

    public static Optional<SessionCookieIds> parseSessionCookie(Map<String, String> headers) {
        if (headers == null
                || headers.isEmpty()
                || !headers.containsKey(REQUEST_COOKIE_HEADER)
                || headers.get(REQUEST_COOKIE_HEADER).isEmpty()) {
            return Optional.empty();
        }

        final String COOKIE_REGEX = "gs=(?<sid>[^.;]+)\\.(?<csid>[^.;]+);";

        String cookies = headers.getOrDefault(REQUEST_COOKIE_HEADER, "");

        LOGGER.debug("Session Cookie: {}", cookies);

        Matcher cookiesMatcher = Pattern.compile(COOKIE_REGEX).matcher(cookies);

        if (cookiesMatcher.find()) {
            final String sid = cookiesMatcher.group("sid");
            final String csid = cookiesMatcher.group("csid");

            return Optional.of(
                    new SessionCookieIds() {
                        public String getSessionId() {
                            return sid;
                        }

                        public String getClientSessionId() {
                            return csid;
                        }
                    });
        } else {
            LOGGER.warn("Unable to parse Session Cookie: {}", cookies);
            return Optional.empty();
        }
    }

    public interface SessionCookieIds {
        String getSessionId();

        String getClientSessionId();
    }
}
