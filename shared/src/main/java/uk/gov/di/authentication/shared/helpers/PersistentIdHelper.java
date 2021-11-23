package uk.gov.di.authentication.shared.helpers;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.Map;
import java.util.Objects;

public class PersistentIdHelper {

    private static final Logger LOG = LogManager.getLogger(PersistentIdHelper.class);
    public static final String PERSISTENT_ID_HEADER_NAME = "di-persistent-session-id";
    public static final String PERSISTENT_ID_UNKNOWN_VALUE = "unknown";

    public static String extractPersistentIdFromHeaders(Map<String, String> headers) {
        if (Objects.isNull(headers)
                || !headers.containsKey(PERSISTENT_ID_HEADER_NAME)
                || headers.get(PERSISTENT_ID_HEADER_NAME) == null) {
            return PERSISTENT_ID_UNKNOWN_VALUE;
        }
        LOG.info("PersistentID on request: {}", headers.get(PERSISTENT_ID_HEADER_NAME));
        return headers.get(PERSISTENT_ID_HEADER_NAME);
    }

    public static String extractPersistentIdFromCookieHeader(Map<String, String> headers) {
        return CookieHelper.parsePersistentCookie(headers).orElse(PERSISTENT_ID_UNKNOWN_VALUE);
    }
}
