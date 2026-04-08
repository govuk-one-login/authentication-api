package uk.gov.di.orchestration.shared.helpers;

import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mockStatic;
import static uk.gov.di.orchestration.shared.helpers.PersistentIdHelper.isValidPersistentSessionCookieWithDoubleDashedTimestamp;

class PersistentIdHelperTest {
    private static final String ARBITRARY_UNIX_TIMESTAMP = "1700558480962";
    private static final String NEW_ID = "lML1nhHXgGC9o-7efoVoFBJGve0";
    private static final String PERSISTENT_SESSION_ID_COOKIE_VALUE =
            IdGenerator.generate() + "--" + ARBITRARY_UNIX_TIMESTAMP;

    @Test
    void shouldReturnPersistentIdWhenExistsInHeader() {
        Map<String, String> inputHeaders =
                Map.of(
                        PersistentIdHelper.PERSISTENT_ID_HEADER_NAME,
                        PERSISTENT_SESSION_ID_COOKIE_VALUE);
        String persistentId = PersistentIdHelper.extractPersistentIdFromHeaders(inputHeaders);

        assertThat(persistentId, equalTo(PERSISTENT_SESSION_ID_COOKIE_VALUE));
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
                String.format(
                        "Version=1; di-persistent-session-id=%s;gs=session-id.456;cookies_preferences_set={\"analytics\":true};name=ts",
                        PERSISTENT_SESSION_ID_COOKIE_VALUE);
        Map<String, String> inputHeaders = Map.of(CookieHelper.REQUEST_COOKIE_HEADER, cookieString);
        String persistentId = PersistentIdHelper.extractPersistentIdFromCookieHeader(inputHeaders);

        assertThat(persistentId, equalTo(PERSISTENT_SESSION_ID_COOKIE_VALUE));
    }

    @Test
    void shouldReturnUnknownWhenPersistentCookieIsNotPresent() {
        String cookieString =
                "Version=1; gs=session-id.456;cookies_preferences_set={\"analytics\":true};name=ts";
        Map<String, String> inputHeaders = Map.of(CookieHelper.REQUEST_COOKIE_HEADER, cookieString);
        String persistentId = PersistentIdHelper.extractPersistentIdFromCookieHeader(inputHeaders);

        assertThat(persistentId, equalTo(PersistentIdHelper.PERSISTENT_ID_UNKNOWN_VALUE));
    }

    @Test
    void
            shouldReturnExistingPersistentIdButAppendTimestampInGetExistingOrCreateWhenOldFormatExists() {
        String cookieString =
                String.format(
                        "Version=1; di-persistent-session-id=%s;gs=session-id.456;cookies_preferences_set={\"analytics\":true};name=ts",
                        PERSISTENT_SESSION_ID_COOKIE_VALUE);
        Map<String, String> inputHeaders = Map.of(CookieHelper.REQUEST_COOKIE_HEADER, cookieString);
        String persistentId =
                PersistentIdHelper.getExistingOrCreateNewPersistentSessionId(inputHeaders);
        assertTrue(isValidPersistentSessionCookieWithDoubleDashedTimestamp(persistentId));
    }

    @Test
    void
            shouldReturnExistingPersistentIdAndNotAppendNewTimestampInGetExistingOrCreateWhenNewFormatExists() {
        String cookieString =
                String.format(
                        "Version=1; di-persistent-session-id=%s;gs=session-id.456;cookies_preferences_set={\"analytics\":true};name=ts",
                        PERSISTENT_SESSION_ID_COOKIE_VALUE);
        Map<String, String> inputHeaders = Map.of(CookieHelper.REQUEST_COOKIE_HEADER, cookieString);
        String persistentId =
                PersistentIdHelper.getExistingOrCreateNewPersistentSessionId(inputHeaders);
        assertTrue(isValidPersistentSessionCookieWithDoubleDashedTimestamp(persistentId));
        assertTrue(persistentId.contains(PERSISTENT_SESSION_ID_COOKIE_VALUE));
    }

    // This relates to a short period where it was possible to have a format like
    // --1700558480962--1700558480963--1700558480964; see commit
    // 75a10df4376397d5a454b87b5cee689e13a71e20; will not be needed from 26/05/2025
    @Test
    void shouldReturnNewPersistentIdWithATimestampWhenCorruptedFormatExists() {
        String corruptedPersistentId = "--1700558480962--1700558480963";

        String cookieString =
                String.format(
                        "Version=1; di-persistent-session-id=%s;gs=session-id.456;cookies_preferences_set={\"analytics\":true};name=ts",
                        corruptedPersistentId);
        Map<String, String> inputHeaders = Map.of(CookieHelper.REQUEST_COOKIE_HEADER, cookieString);
        String persistentId =
                PersistentIdHelper.getExistingOrCreateNewPersistentSessionId(inputHeaders);
        assertTrue(isValidPersistentSessionCookieWithDoubleDashedTimestamp(persistentId));
        assertFalse(persistentId.contains(corruptedPersistentId));
    }

    @Test
    void shouldAppendTimestampToPersistentIdWhenMissing() {
        String oldPersistentId = IdGenerator.generate();

        String cookieString =
                String.format(
                        "Version=1; di-persistent-session-id=%s;gs=session-id.456;cookies_preferences_set={\"analytics\":true};name=ts",
                        oldPersistentId);
        Map<String, String> inputHeaders = Map.of(CookieHelper.REQUEST_COOKIE_HEADER, cookieString);
        String persistentId =
                PersistentIdHelper.getExistingOrCreateNewPersistentSessionId(inputHeaders);
        assertTrue(isValidPersistentSessionCookieWithDoubleDashedTimestamp(persistentId));
        assertTrue(persistentId.startsWith(oldPersistentId));
    }

    @Test
    void shouldGenerateNewPersistentIdFromGetExistingOrCreateWhenMissing() {
        try (var mockIdGenerator = mockStatic(IdGenerator.class)) {
            mockIdGenerator.when(IdGenerator::generate).thenReturn(NEW_ID);

            String cookieString =
                    "Version=1; gs=session-id.456;cookies_preferences_set={\"analytics\":true};name=ts";
            Map<String, String> inputHeaders =
                    Map.of(CookieHelper.REQUEST_COOKIE_HEADER, cookieString);

            String persistentId =
                    PersistentIdHelper.getExistingOrCreateNewPersistentSessionId(inputHeaders);

            assertTrue(isValidPersistentSessionCookieWithDoubleDashedTimestamp(persistentId));
            assertTrue(persistentId.startsWith(NEW_ID));
        }
    }
}
