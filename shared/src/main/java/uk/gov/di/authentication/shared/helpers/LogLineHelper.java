package uk.gov.di.authentication.shared.helpers;

import org.apache.logging.log4j.ThreadContext;
import org.apache.logging.log4j.message.StringMapMessage;

import java.util.Objects;

import static uk.gov.di.authentication.shared.helpers.InputSanitiser.sanitiseBase64;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.LogFieldName.LOG_ERROR_CODE;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.LogFieldName.LOG_ERROR_DESCRIPTION;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.LogFieldName.LOG_MESSAGE_DESCRIPTION;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.LogFieldName.SESSION_ID;

public class LogLineHelper {

    public static final String UNKNOWN = "unknown";

    public enum LogFieldName {
        SESSION_ID("sessionId", true),
        CLIENT_SESSION_ID("clientSessionId", true),
        GOVUK_SIGNIN_JOURNEY_ID("govukSigninJourneyId", true),
        PERSISTENT_SESSION_ID("persistentSessionId", true),
        AWS_REQUEST_ID("awsRequestId", false),
        CLIENT_ID("clientId", true),
        CLIENT_NAME("clientName", false),
        JOURNEY_TYPE("journeyType", false),
        LOG_ERROR_DESCRIPTION("errorDescription", false),
        LOG_ERROR_CODE("errorCode", false),
        LOG_MESSAGE_DESCRIPTION("description", false);

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

    public static void attachSessionIdToLogs(String sessionId) {
        attachLogFieldToLogs(SESSION_ID, sessionId);
    }

    public static void updateAttachedSessionIdToLogs(String sessionId) {
        if (ThreadContext.containsKey(SESSION_ID.getLogFieldName())) {
            ThreadContext.remove(SESSION_ID.getLogFieldName());
        }
        attachSessionIdToLogs(sessionId);
    }

    public static StringMapMessage buildLogMessage(String message) {
        return new StringMapMessage().with(LOG_MESSAGE_DESCRIPTION.getLogFieldName(), message);
    }

    public static StringMapMessage buildErrorMessage(String message, String errorDescription) {
        return buildLogMessage(message)
                .with(
                        LOG_ERROR_DESCRIPTION.getLogFieldName(),
                        Objects.requireNonNullElse(errorDescription, "Unknown"));
    }

    public static StringMapMessage buildErrorMessage(String message, Exception e) {
        return buildLogMessage(message).with(LOG_ERROR_DESCRIPTION.getLogFieldName(), e);
    }

    public static StringMapMessage buildErrorMessage(
            String message, String errorDescription, int errorCode) {
        return buildErrorMessage(message, errorDescription, Integer.toString(errorCode));
    }

    public static StringMapMessage buildErrorMessage(
            String message, String errorDescription, String errorCode) {
        return buildErrorMessage(message, errorDescription)
                .with(
                        LOG_ERROR_CODE.getLogFieldName(),
                        Objects.requireNonNullElse(errorCode, "Unknown"));
    }
}
