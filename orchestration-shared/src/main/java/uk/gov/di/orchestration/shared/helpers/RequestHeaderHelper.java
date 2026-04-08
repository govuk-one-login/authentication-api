package uk.gov.di.orchestration.shared.helpers;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.Map;
import java.util.Optional;

public final class RequestHeaderHelper {

    private static final Logger LOG = LogManager.getLogger(RequestHeaderHelper.class);

    private RequestHeaderHelper() {}

    public static boolean headersContainValidOptionalHeader(
            Map<String, String> headers, String headerName, boolean matchLowerCase) {
        return headersContainValidHeader(headers, headerName, matchLowerCase, false);
    }

    public static boolean headersContainValidHeader(
            Map<String, String> headers, String headerName, boolean matchLowerCase) {
        return headersContainValidHeader(headers, headerName, matchLowerCase, true);
    }

    private static boolean headersContainValidHeader(
            Map<String, String> headers,
            String headerName,
            boolean matchLowerCase,
            boolean warnOnMissing) {
        var warnLevel = warnOnMissing ? Level.WARN : Level.TRACE;
        if (headers == null || headers.isEmpty()) {
            LOG.log(
                    warnLevel,
                    "All headers are missing or empty when looking for header {}",
                    headerName);
            return false;
        } else if (!matchLowerCase && headers.containsKey(headerName)) {
            LOG.trace("Found header {}, matchLowerCase={}", headerName, matchLowerCase);
            return true;
        } else if (matchLowerCase
                && (headers.containsKey(headerName)
                        && headers.containsKey(headerName.toLowerCase()))) {
            LOG.warn(
                    "Found both headers {} and lowercase version, matchLowerCase={}",
                    headerName,
                    matchLowerCase);
            return false;
        } else if (matchLowerCase
                && (headers.containsKey(headerName)
                        || headers.containsKey(headerName.toLowerCase()))) {
            LOG.trace(
                    "Found header {} lowercase version, matchLowerCase={}",
                    headerName,
                    matchLowerCase);
            return true;
        } else {
            LOG.log(
                    warnLevel,
                    "Header {} is missing, matchLowerCase={}",
                    headerName,
                    matchLowerCase);
            return false;
        }
    }

    public static Optional<String> getHeaderValueFromHeadersOpt(
            Map<String, String> headers, String headerName, boolean matchLowerCase) {
        return Optional.ofNullable(getHeaderValueFromHeaders(headers, headerName, matchLowerCase));
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
