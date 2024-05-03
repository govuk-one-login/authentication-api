package uk.gov.di.authentication.shared.helpers;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.Map;

public final class RequestHeaderHelper {

    private static final Logger LOG = LogManager.getLogger(RequestHeaderHelper.class);

    private RequestHeaderHelper() {}

    public static boolean headersContainValidHeader(
            Map<String, String> headers, String headerName, boolean matchLowerCase) {
        return getHeaderValueFromHeaders(headers, headerName, matchLowerCase) != null;
    }

    public static String getHeaderValueFromHeaders(
            Map<String, String> headers, String headerName, boolean matchLowerCase) {
        if (headers == null || headers.isEmpty()) {
            return null;
        } else if (headers.containsKey(headerName)) {
            return headers.get(headerName);
        } else if (matchLowerCase && headers.containsKey(headerName.toLowerCase())) {
            return headers.get(headerName.toLowerCase());
        } else {
            return null;
        }
    }

    public static String getHeaderValueOrElse(
            Map<String, String> headers, String headerName, String orElse) {
        String headerValue = getHeaderValueFromHeaders(headers, headerName, false);
        return headerValue != null ? headerValue : orElse;
    }
}
