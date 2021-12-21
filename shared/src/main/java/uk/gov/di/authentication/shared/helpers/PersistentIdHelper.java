package uk.gov.di.authentication.shared.helpers;

import java.util.Map;
import java.util.Objects;

public class PersistentIdHelper {

    public static final String PERSISTENT_ID_HEADER_NAME = "di-persistent-session-id";
    public static final String PERSISTENT_ID_UNKNOWN_VALUE = "unknown";

    public static String extractPersistentIdFromHeaders(Map<String, String> headers) {
        if (Objects.isNull(headers)
                || !headers.containsKey(PERSISTENT_ID_HEADER_NAME)
                || headers.get(PERSISTENT_ID_HEADER_NAME) == null) {
            return PERSISTENT_ID_UNKNOWN_VALUE;
        }
        return InputSanitiser.sanitiseBase64(headers.get(PERSISTENT_ID_HEADER_NAME))
                .orElse(PERSISTENT_ID_UNKNOWN_VALUE);
    }

    public static String extractPersistentIdFromCookieHeader(Map<String, String> headers) {
        return CookieHelper.parsePersistentCookie(headers)
                .flatMap(InputSanitiser::sanitiseBase64)
                .orElse(PERSISTENT_ID_UNKNOWN_VALUE);
    }

    public static String getExistingOrCreateNewPersistentSessionId(Map<String, String> headers) {
        return CookieHelper.parsePersistentCookie(headers)
                .flatMap(InputSanitiser::sanitiseBase64)
                .orElse(IdGenerator.generate());
    }
}
