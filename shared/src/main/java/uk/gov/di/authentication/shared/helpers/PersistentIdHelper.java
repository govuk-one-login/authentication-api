package uk.gov.di.authentication.shared.helpers;

import java.util.Map;
import java.util.Objects;

import static uk.gov.di.authentication.shared.helpers.CookieHelper.appendTimestampToCookieValue;

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
        // due to change in persistent session ID format in November 2023, this could be in the old
        // format <ID> or new format <ID>--<timestamp> e.g.
        // U8gFw6gLpuWWHyOvj21CGphM60--1700505785611
        var parsedOrGeneratedCookie =
                CookieHelper.parsePersistentCookie(headers)
                        .orElse(appendTimestampToCookieValue(IdGenerator.generate()));

        String VALID_PERSISTENT_SESSION_ID_FORMAT_REGEX = "[A-Za-z0-9-_]{27}--\\d{13}";
        if (parsedOrGeneratedCookie.matches(VALID_PERSISTENT_SESSION_ID_FORMAT_REGEX)) {
            return parsedOrGeneratedCookie;
        }

        String sanitisedCookie =
                InputSanitiser.sanitiseBase64(parsedOrGeneratedCookie)
                        .orElseThrow(
                                () ->
                                        new RuntimeException(
                                                "Unable to sanitise the following cookie value: "
                                                        + parsedOrGeneratedCookie));

        return appendTimestampToCookieValue(sanitisedCookie);
    }
}
