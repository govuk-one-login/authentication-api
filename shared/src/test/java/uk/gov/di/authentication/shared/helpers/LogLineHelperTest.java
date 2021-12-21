package uk.gov.di.authentication.shared.helpers;

import org.apache.logging.log4j.ThreadContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.entity.Session;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.LogFieldName.SESSION_ID;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachLogFieldToLogs;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachSessionIdToLogs;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.updateAttachedSessionIdToLogs;

class LogLineHelperTest {

    @BeforeEach
    void setup() {
        ThreadContext.clearAll();
    }

    @Test
    void shouldAttachSessionIdToThreadContextUsingAttachLogField() {
        attachLogFieldToLogs(SESSION_ID, "session-id");

        assertTrue(ThreadContext.containsKey(SESSION_ID.getLogFieldName()));
        assertEquals("session-id", ThreadContext.get(SESSION_ID.getLogFieldName()));
    }

    @Test
    void shouldAttachSessionIdToThreadContextUsingString() {
        attachSessionIdToLogs("session-id");

        assertTrue(ThreadContext.containsKey(SESSION_ID.getLogFieldName()));
        assertEquals("session-id", ThreadContext.get(SESSION_ID.getLogFieldName()));
    }

    @Test
    void shouldAttachSessionIdToThreadContextUsingSession() {
        attachSessionIdToLogs(new Session("session-id"));

        assertTrue(ThreadContext.containsKey(SESSION_ID.getLogFieldName()));
        assertEquals("session-id", ThreadContext.get(SESSION_ID.getLogFieldName()));
    }

    @Test
    void shouldUpdateAttachedSessionIdToThreadContext() {
        attachSessionIdToLogs("session-id");
        updateAttachedSessionIdToLogs("updated-session-id");

        assertTrue(ThreadContext.containsKey(SESSION_ID.getLogFieldName()));
        assertEquals(1, ThreadContext.getContext().size());
        assertEquals("updated-session-id", ThreadContext.get(SESSION_ID.getLogFieldName()));
    }
}
