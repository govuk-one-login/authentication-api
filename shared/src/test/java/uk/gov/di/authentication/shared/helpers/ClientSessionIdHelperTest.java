package uk.gov.di.authentication.shared.helpers;

import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;

class ClientSessionIdHelperTest {

    private static final String SESSION_ID_HEADER_NAME = "Client-Session-Id";
    private static final String SESSION_ID_VALUE = "some_session_id";

    @Test
    void shouldExtractSessionIdFromHeaders() {
        Map<String, String> inputHeaders =
                Collections.singletonMap(SESSION_ID_HEADER_NAME, SESSION_ID_VALUE);
        String sessionId = ClientSessionIdHelper.extractSessionIdFromHeaders(inputHeaders);

        assertThat(sessionId, equalTo(SESSION_ID_VALUE));
    }

    @Test
    void shouldReturnUnknownIfSessionIdHeaderIsNotPresent() {
        Map<String, String> inputHeaders = Collections.emptyMap();
        String sessionId = ClientSessionIdHelper.extractSessionIdFromHeaders(inputHeaders);

        assertThat(sessionId, equalTo(ClientSessionIdHelper.SESSION_ID_UNKNOWN_VALUE));
    }

    @Test
    void shouldReturnUnknownIfSessionIdIsNull() {
        Map<String, String> inputHeaders = new HashMap<>();
        inputHeaders.put(SESSION_ID_HEADER_NAME, null);
        String sessionId = ClientSessionIdHelper.extractSessionIdFromHeaders(inputHeaders);

        assertThat(sessionId, equalTo(ClientSessionIdHelper.SESSION_ID_UNKNOWN_VALUE));
    }
}
