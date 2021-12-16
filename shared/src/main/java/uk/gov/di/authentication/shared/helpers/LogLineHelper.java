package uk.gov.di.authentication.shared.helpers;

import org.apache.logging.log4j.ThreadContext;
import uk.gov.di.authentication.shared.entity.Session;

public class LogLineHelper {

    public static void attachSessionIdToLogs(Session session) {
        ThreadContext.put("sessionId", session.getSessionId());
    }

    public static void attachSessionIdToLogs(String sessionId) {
        ThreadContext.put("sessionId", sessionId);
    }

    public static void updateAttachedSessionIdToLogs(String sessionId) {
        if (ThreadContext.containsKey("sessionId")) {
            ThreadContext.remove("sessionId");
        }
        attachSessionIdToLogs(sessionId);
    }
}
