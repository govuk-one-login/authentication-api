package uk.gov.di.orchestration.shared.helpers;

import io.opentelemetry.api.trace.Span;
import org.apache.logging.log4j.ThreadContext;

import static uk.gov.di.orchestration.shared.helpers.InputSanitiser.sanitiseBase64;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.ORCH_SESSION_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.SESSION_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.TRACE_ID;

public class LogLineHelper {

    public static final String UNKNOWN = "unknown";

    public enum LogFieldName {
        SESSION_ID("sessionId", true),
        ORCH_SESSION_ID("orchSessionId", true),
        CLIENT_SESSION_ID("clientSessionId", true),
        GOVUK_SIGNIN_JOURNEY_ID("govukSigninJourneyId", true),
        PERSISTENT_SESSION_ID("persistentSessionId", true),
        AWS_REQUEST_ID("awsRequestId", false),
        CLIENT_ID("clientId", true),
        CLIENT_NAME("clientName", false),
        TRACE_ID("traceId", false);

        private final String logFieldName;
        private boolean isBase64;

        LogFieldName(String fieldName, boolean isBase64) {
            this.logFieldName = fieldName;
            this.isBase64 = isBase64;
        }

        String getLogFieldName() {
            return logFieldName;
        }
    }

    public static void attachLogFieldToLogs(LogFieldName logFieldName, String value) {
        if (logFieldName.isBase64 && sanitiseBase64(value).isEmpty()) {
            ThreadContext.put(logFieldName.getLogFieldName(), "invalid-identifier");
        } else {
            ThreadContext.put(logFieldName.getLogFieldName(), value);
        }
    }

    public static void updateAttachedLogFieldToLogs(LogFieldName logFieldName, String value) {
        if (ThreadContext.containsKey(logFieldName.getLogFieldName())) {
            ThreadContext.remove(logFieldName.getLogFieldName());
        }
        attachLogFieldToLogs(logFieldName, value);
    }

    public static void attachSessionIdToLogs(String sessionId) {
        attachLogFieldToLogs(SESSION_ID, sessionId);
    }

    public static void updateAttachedSessionIdToLogs(String sessionId) {
        if (ThreadContext.containsKey(SESSION_ID.getLogFieldName())) {
            ThreadContext.remove(SESSION_ID.getLogFieldName());
        }
        attachSessionIdToLogs(sessionId);
    }

    public static void attachOrchSessionIdToLogs(String orchSessionId) {
        attachLogFieldToLogs(ORCH_SESSION_ID, orchSessionId);
    }

    public static void attachTraceId() {
        // Adapted from
        // https://docs.dynatrace.com/docs/analyze-explore-automate/logs/lma-log-enrichment#retrieve-span-and-trace-ids
        var spanContext = Span.current().getSpanContext();
        if (spanContext.isValid()) {
            attachLogFieldToLogs(TRACE_ID, spanContext.getTraceId());
        }
    }
}
