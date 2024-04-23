package uk.gov.di.authentication.shared.helpers;

import java.util.Map;
import java.util.Objects;

public class ClientSessionIdHelper {
    public static final String SESSION_ID_HEADER_NAME = "Client-Session-Id";

    public static final String SESSION_ID_UNKNOWN_VALUE = "unknown";

    public static String extractSessionIdFromHeaders(Map<String, String> headers) {
        if (Objects.isNull(headers)
                || !headers.containsKey(SESSION_ID_HEADER_NAME)
                || headers.get(SESSION_ID_HEADER_NAME) == null) {
            return SESSION_ID_UNKNOWN_VALUE;
        }
        return InputSanitiser.sanitiseBase64(headers.get(SESSION_ID_HEADER_NAME))
                .orElse(SESSION_ID_UNKNOWN_VALUE);
    }
}
