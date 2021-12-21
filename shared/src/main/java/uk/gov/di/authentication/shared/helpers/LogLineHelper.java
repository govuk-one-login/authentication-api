package uk.gov.di.authentication.shared.helpers;

import org.apache.logging.log4j.ThreadContext;
import uk.gov.di.authentication.shared.entity.Session;

import static uk.gov.di.authentication.shared.helpers.LogLineHelper.LogFieldName.SESSION_ID;

public class LogLineHelper {

    public enum LogFieldName {
        SESSION_ID("sessionId"),
        PERSISTENT_SESSION_ID("persistentSessionId"),
        AWS_REQUEST_ID("awsRequestId");

        private String logFieldName;

        LogFieldName(String fieldName) {
            this.logFieldName = fieldName;
        }

        String getLogFieldName() {
            return logFieldName;
        }
    }

    public static void attachLogFieldToLogs(LogFieldName logFieldName, String value) {
        ThreadContext.put(logFieldName.getLogFieldName(), value);
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
