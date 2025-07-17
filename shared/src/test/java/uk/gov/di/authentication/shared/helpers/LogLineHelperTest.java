package uk.gov.di.authentication.shared.helpers;

import io.opentelemetry.api.trace.Span;
import io.opentelemetry.api.trace.SpanContext;
import io.opentelemetry.api.trace.SpanId;
import io.opentelemetry.api.trace.TraceFlags;
import io.opentelemetry.api.trace.TraceId;
import io.opentelemetry.api.trace.TraceState;
import io.opentelemetry.context.Context;
import io.opentelemetry.context.Scope;
import org.apache.logging.log4j.ThreadContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.LogFieldName.SESSION_ID;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.LogFieldName.TRACE_ID;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachLogFieldToLogs;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachSessionIdToLogs;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachTraceId;
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

    @Test
    void shouldNotLogTraceIdIfUnavailable() {
        attachTraceId();

        assertFalse(ThreadContext.containsKey(TRACE_ID.getLogFieldName()));
    }

    @Test
    void shouldLogSpanAndTraceIdIfAvailable() {
        var spanContext =
                SpanContext.create(
                        TraceId.fromLongs(1, 2),
                        SpanId.fromLong(3),
                        TraceFlags.getDefault(),
                        TraceState.getDefault());
        var span = Span.wrap(spanContext);
        var context = span.storeInContext(Context.root());

        try (Scope ignored = context.makeCurrent()) {
            attachTraceId();

            assertTrue(ThreadContext.containsKey(TRACE_ID.getLogFieldName()));
            assertEquals(spanContext.getTraceId(), ThreadContext.get(TRACE_ID.getLogFieldName()));
        }
    }
}
