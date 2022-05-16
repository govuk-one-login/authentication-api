package uk.gov.di.authentication.shared.helpers;

import org.apache.logging.log4j.ThreadContext;
import uk.gov.di.authentication.shared.entity.Session;

import static uk.gov.di.authentication.shared.helpers.InputSanitiser.sanitiseBase64;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.LogFieldName.SESSION_ID;

public class LogLineHelper {

    public static final String UNKNOWN = "unknown";

    public enum LogFieldName {
        SESSION_ID("sessionId", true),
        CLIENT_SESSION_ID("clientSessionId", true),
        PERSISTENT_SESSION_ID("persistentSessionId", true),
        AWS_REQUEST_ID("awsRequestId", false),
        CLIENT_ID("clientId", true);

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

    public static void attachSessionIdToLogs(Session session) {
        attachLogFieldToLogs(SESSION_ID, session.getSessionId());
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
}
