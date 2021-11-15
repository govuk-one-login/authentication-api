package uk.gov.di.authentication.shared.helpers;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.Map;

public final class RequestHeaderHelper {

    private static final Logger LOGGER = LogManager.getLogger(RequestHeaderHelper.class);

    private RequestHeaderHelper() {}

    public static boolean headersContainValidHeader(
            Map<String, String> headers, String headerName, boolean matchLowerCase) {
        if (headers == null || headers.isEmpty()) {
            LOGGER.error("All headers are missing or empty when looking for header {}", headerName);
            return false;
        } else if (!matchLowerCase && headers.containsKey(headerName)) {
            LOGGER.info("Found header {}, matchLowerCase={}", headerName, matchLowerCase);
            return true;
        } else if (matchLowerCase
                && (headers.containsKey(headerName)
                        && headers.containsKey(headerName.toLowerCase()))) {
            LOGGER.error(
                    "Found both headers {} and lowercase version, matchLowerCase={}",
                    headerName,
                    matchLowerCase);
            return false;
        } else if (matchLowerCase
                && (headers.containsKey(headerName)
                        || headers.containsKey(headerName.toLowerCase()))) {
            LOGGER.info(
                    "Found header {} lowercase version, matchLowerCase={}",
                    headerName,
                    matchLowerCase);
            return true;
        } else {
            LOGGER.warn("Header {} is missing, matchLowerCase={}", headerName, matchLowerCase);
            return false;
        }
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
}
