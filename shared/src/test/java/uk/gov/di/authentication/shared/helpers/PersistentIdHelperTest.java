package uk.gov.di.authentication.shared.helpers;

import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;

class PersistentIdHelperTest {

    @Test
    void shouldReturnPersistentIdWhenExistsInHeader() {
        String persistentIdInputHeader = "some-persistent-id-value";
        Map<String, String> inputHeaders =
                Map.of(PersistentIdHelper.PERSISTENT_ID_HEADER_NAME, persistentIdInputHeader);
        String persistentId = PersistentIdHelper.extractPersistentIdFromHeaders(inputHeaders);

        assertThat(persistentId, equalTo(persistentIdInputHeader));
    }

    @Test
    void shouldReturnUnknownIfPersistentIdHeaderIsNotPresent() {
        Map<String, String> inputHeaders = Collections.emptyMap();
        String persistentId = PersistentIdHelper.extractPersistentIdFromHeaders(inputHeaders);

        assertThat(persistentId, equalTo(PersistentIdHelper.PERSISTENT_ID_UNKNOWN_VALUE));
    }

    @Test
    void shouldReturnUnknownIfPersistentIdIsNull() {
        Map<String, String> inputHeaders = new HashMap<>();
        inputHeaders.put(PersistentIdHelper.PERSISTENT_ID_HEADER_NAME, null);
        String persistentId = PersistentIdHelper.extractPersistentIdFromHeaders(inputHeaders);

        assertThat(persistentId, equalTo(PersistentIdHelper.PERSISTENT_ID_UNKNOWN_VALUE));
    }

    @Test
    void shouldReturnPersistentIdFromCookieHeaderWhenExists() {
        String cookieString =
                "Version=1; di-persistent-session-id=a-persistent-id;gs=session-id.456;cookies_preferences_set={\"analytics\":true};name=ts";
        Map<String, String> inputHeaders = Map.of(CookieHelper.REQUEST_COOKIE_HEADER, cookieString);
        String persistentId = PersistentIdHelper.extractPersistentIdFromCookieHeader(inputHeaders);

        assertThat(persistentId, equalTo("a-persistent-id"));
    }

    @Test
    void shouldReturnUnknownWhenPersistentCookieIsNotPresent() {
        String cookieString =
                "Version=1; gs=session-id.456;cookies_preferences_set={\"analytics\":true};name=ts";
        Map<String, String> inputHeaders = Map.of(CookieHelper.REQUEST_COOKIE_HEADER, cookieString);
        String persistentId = PersistentIdHelper.extractPersistentIdFromCookieHeader(inputHeaders);

        assertThat(persistentId, equalTo(PersistentIdHelper.PERSISTENT_ID_UNKNOWN_VALUE));
    }
}
