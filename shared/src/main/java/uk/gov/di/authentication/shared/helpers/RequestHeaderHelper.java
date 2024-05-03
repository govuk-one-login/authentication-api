package uk.gov.di.authentication.shared.helpers;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.Map;
import java.util.Optional;

public final class RequestHeaderHelper {

    private static final Logger LOG = LogManager.getLogger(RequestHeaderHelper.class);

    private RequestHeaderHelper() {}

    public static boolean headersContainValidHeader(
            Map<String, String> headers, String headerName, boolean matchLowerCase) {
        return getOptionalHeaderValueFromHeaders(headers, headerName, matchLowerCase).isPresent();
    }

    public static String getHeaderValueFromHeaders(
            Map<String, String> headers, String headerName, boolean matchLowerCase) {
        return getOptionalHeaderValueFromHeaders(headers, headerName, matchLowerCase).orElse(null);
    }

    public static Optional<String> getOptionalHeaderValueFromHeaders(
            Map<String, String> headers, String headerName, boolean matchLowerCase) {
        if (headers == null || headers.isEmpty()) {
            return Optional.empty();
        } else if (headers.containsKey(headerName)) {
            return Optional.of(headers.get(headerName));
        } else if (matchLowerCase && headers.containsKey(headerName.toLowerCase())) {
            return Optional.of(headers.get(headerName.toLowerCase()));
        } else {
            return Optional.empty();
        }
    }

    public static String getHeaderValueOrElse(
            Map<String, String> headers, String headerName, String orElse) {
        return getOptionalHeaderValueFromHeaders(headers, headerName, false).orElse(orElse);
    }
}
