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

    private final String identifier = IdGenerator.generate();

    @BeforeEach
    void setup() {
        ThreadContext.clearAll();
    }

    @Test
    void shouldAttachSessionIdToThreadContextUsingAttachLogField() {
        attachLogFieldToLogs(SESSION_ID, identifier);

        assertTrue(ThreadContext.containsKey(SESSION_ID.getLogFieldName()));
        assertEquals(identifier, ThreadContext.get(SESSION_ID.getLogFieldName()));
    }

    @Test
    void shouldAttachSessionIdToThreadContextUsingString() {
        attachSessionIdToLogs(identifier);

        assertTrue(ThreadContext.containsKey(SESSION_ID.getLogFieldName()));
        assertEquals(identifier, ThreadContext.get(SESSION_ID.getLogFieldName()));
    }

    @Test
    void shouldAttachSessionIdToThreadContextUsingSession() {
        attachSessionIdToLogs(new Session(identifier));

        assertTrue(ThreadContext.containsKey(SESSION_ID.getLogFieldName()));
        assertEquals(identifier, ThreadContext.get(SESSION_ID.getLogFieldName()));
    }

    @Test
    void shouldUpdateAttachedSessionIdToThreadContext() {
        var newIdentifier = IdGenerator.generate();

        attachSessionIdToLogs(identifier);
        updateAttachedSessionIdToLogs(newIdentifier);

        assertTrue(ThreadContext.containsKey(SESSION_ID.getLogFieldName()));
        assertEquals(1, ThreadContext.getContext().size());
        assertEquals(newIdentifier, ThreadContext.get(SESSION_ID.getLogFieldName()));
    }

    @Test
    void shouldLogInvalidParameterIfFormatIsWrong() {
        var badIdentifier = "not-@-b@se64-identifier";

        attachSessionIdToLogs(badIdentifier);

        assertTrue(ThreadContext.containsKey(SESSION_ID.getLogFieldName()));
        assertEquals("invalid-identifier", ThreadContext.get(SESSION_ID.getLogFieldName()));
    }
}
