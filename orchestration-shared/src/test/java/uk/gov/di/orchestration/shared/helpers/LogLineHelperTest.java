package uk.gov.di.orchestration.shared.helpers;

import org.apache.logging.log4j.ThreadContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.LOG_ERROR_CODE;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.LOG_ERROR_DESCRIPTION;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.LOG_MESSAGE_DESCRIPTION;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.ORCH_SESSION_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.SESSION_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.attachLogFieldToLogs;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.attachOrchSessionIdToLogs;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.attachSessionIdToLogs;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.updateAttachedSessionIdToLogs;

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
    void shouldUpdateAttachedSessionIdToThreadContext() {
        var newIdentifier = IdGenerator.generate();

        attachSessionIdToLogs(identifier);
        updateAttachedSessionIdToLogs(newIdentifier);

        assertTrue(ThreadContext.containsKey(SESSION_ID.getLogFieldName()));
        assertEquals(1, ThreadContext.getContext().size());
        assertEquals(newIdentifier, ThreadContext.get(SESSION_ID.getLogFieldName()));
    }

    @Test
    void shouldAttachOrchSessionIdToThreadContextUsingString() {
        attachOrchSessionIdToLogs(identifier);

        assertTrue(ThreadContext.containsKey(ORCH_SESSION_ID.getLogFieldName()));
        assertEquals(identifier, ThreadContext.get(ORCH_SESSION_ID.getLogFieldName()));
    }

    @Test
    void shouldLogInvalidParameterIfFormatIsWrong() {
        var badIdentifier = "not-@-b@se64-identifier";

        attachSessionIdToLogs(badIdentifier);

        assertTrue(ThreadContext.containsKey(SESSION_ID.getLogFieldName()));
        assertEquals("invalid-identifier", ThreadContext.get(SESSION_ID.getLogFieldName()));
    }

    @Test
    void buildLogMessageShouldCorrectlyAddDescription() {
        var logMessage = LogLineHelper.buildLogMessage("Test message");

        assertEquals("Test message", logMessage.get(LOG_MESSAGE_DESCRIPTION.getLogFieldName()));
    }

    @Test
    void buildErrorMessageShouldAttachErrorDescription() {
        var logMessage = LogLineHelper.buildErrorMessage("Test message", "Error description");

        assertEquals("Test message", logMessage.get(LOG_MESSAGE_DESCRIPTION.getLogFieldName()));
        assertEquals("Error description", logMessage.get(LOG_ERROR_DESCRIPTION.getLogFieldName()));
    }

    @Test
    void buildErrorMessageShouldAttachErrorCode() {
        var logMessage = LogLineHelper.buildErrorMessage("Test message", "Error description", 10);

        assertEquals("Test message", logMessage.get(LOG_MESSAGE_DESCRIPTION.getLogFieldName()));
        assertEquals("Error description", logMessage.get(LOG_ERROR_DESCRIPTION.getLogFieldName()));
        assertEquals("10", logMessage.get(LOG_ERROR_CODE.getLogFieldName()));

        var logMessage2 =
                LogLineHelper.buildErrorMessage("Test message", "Error description", "10");

        assertEquals("Test message", logMessage2.get(LOG_MESSAGE_DESCRIPTION.getLogFieldName()));
        assertEquals("Error description", logMessage2.get(LOG_ERROR_DESCRIPTION.getLogFieldName()));
        assertEquals("10", logMessage2.get(LOG_ERROR_CODE.getLogFieldName()));
    }
}
