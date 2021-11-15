package uk.gov.di.authentication.shared.helpers;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.Collections;
import java.util.Map;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.params.provider.Arguments.arguments;
import static uk.gov.di.authentication.shared.helpers.RequestHeaderHelper.getHeaderValueFromHeaders;
import static uk.gov.di.authentication.shared.helpers.RequestHeaderHelper.headersContainValidHeader;

class RequestHeaderHelperTest {

    private static final Map<String, String> MAP_ONE_ENTRY_UPPER_CASE =
            Map.of("Session-Id", "session-id-123");
    private static final Map<String, String> MAP_TWO_ENTRIES_UPPER_CASE =
            Map.of("Session-Id", "session-id-123", "Client-Session-Id", "client-session-id-123");
    private static final Map<String, String> MAP_ONE_ENTRY_LOWER_CASE =
            Map.of("session-id", "session-id-123");
    private static final Map<String, String> MAP_TWO_ENTRIES_LOWER_CASE =
            Map.of("session-id", "session-id-123", "client-session-id", "client-session-id-123");

    private static Stream<Arguments> headersTestParameters() {
        return Stream.of(
                arguments(null, null, false, false, null),
                arguments(null, null, true, false, null),
                arguments(Collections.emptyMap(), null, false, false, null),
                arguments(Collections.emptyMap(), null, true, false, null),
                arguments(Collections.emptyMap(), "", false, false, null),
                arguments(Collections.emptyMap(), "", true, false, null),
                arguments(MAP_ONE_ENTRY_UPPER_CASE, "Missing-Header", false, false, null),
                arguments(MAP_ONE_ENTRY_UPPER_CASE, "Missing-Header", true, false, null),
                arguments(MAP_TWO_ENTRIES_UPPER_CASE, "Missing-Header", false, false, null),
                arguments(MAP_TWO_ENTRIES_UPPER_CASE, "Missing-Header", true, false, null),
                arguments(MAP_ONE_ENTRY_UPPER_CASE, "Session-Id", false, true, "session-id-123"),
                arguments(MAP_ONE_ENTRY_UPPER_CASE, "Session-Id", true, true, "session-id-123"),
                arguments(
                        MAP_TWO_ENTRIES_UPPER_CASE,
                        "Client-Session-Id",
                        false,
                        true,
                        "client-session-id-123"),
                arguments(
                        MAP_TWO_ENTRIES_UPPER_CASE,
                        "Client-Session-Id",
                        true,
                        true,
                        "client-session-id-123"),
                arguments(MAP_ONE_ENTRY_UPPER_CASE, "session-id", false, false, null),
                arguments(MAP_ONE_ENTRY_UPPER_CASE, "session-id", true, false, null),
                arguments(MAP_TWO_ENTRIES_UPPER_CASE, "client-session-id", false, false, null),
                arguments(MAP_TWO_ENTRIES_UPPER_CASE, "client-session-id", true, false, null),
                arguments(MAP_ONE_ENTRY_LOWER_CASE, "Session-Id", false, false, null),
                arguments(MAP_ONE_ENTRY_LOWER_CASE, "Session-Id", true, true, "session-id-123"),
                arguments(MAP_TWO_ENTRIES_LOWER_CASE, "Client-Session-Id", false, false, null),
                arguments(
                        MAP_TWO_ENTRIES_LOWER_CASE,
                        "Client-Session-Id",
                        true,
                        true,
                        "client-session-id-123"));
    }

    @ParameterizedTest
    @MethodSource("headersTestParameters")
    void testHeadersContainValidHeader(
            Map<String, String> headers,
            String headerName,
            boolean matchLowerCase,
            boolean expectedValidity) {
        assertEquals(
                expectedValidity, headersContainValidHeader(headers, headerName, matchLowerCase));
    }

    @ParameterizedTest
    @MethodSource("headersTestParameters")
    void doIt(
            Map<String, String> headers,
            String headerName,
            boolean matchLowerCase,
            boolean expectedValidity,
            String expectedValue) {
        assertEquals(expectedValue, getHeaderValueFromHeaders(headers, headerName, matchLowerCase));
    }
}
