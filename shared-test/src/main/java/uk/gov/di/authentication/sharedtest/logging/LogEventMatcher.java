package uk.gov.di.authentication.sharedtest.logging;

import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.message.ObjectMessage;
import org.hamcrest.Description;
import org.hamcrest.Matcher;
import org.hamcrest.TypeSafeMatcher;

import java.util.Map;

public class LogEventMatcher {

    public static Matcher<LogEvent> hasObjectMessageProperty(String key, String value) {
        return new TypeSafeMatcher<>() {

            @Override
            @SuppressWarnings("unchecked")
            protected boolean matchesSafely(LogEvent item) {
                var objectMessage = (ObjectMessage) item.getMessage();

                var properties = (Map<String, String>) objectMessage.getParameter();

                return properties.containsKey(key) && properties.get(key).equals(value);
            }

            @Override
            public void describeTo(Description description) {
                description.appendText(
                        "a log event with ObjectMessage property [" + key + ", " + value + "]");
            }
        };
    }

    public static Matcher<LogEvent> doesNotHaveObjectMessageProperty(String key) {
        return new TypeSafeMatcher<>() {

            @Override
            @SuppressWarnings("unchecked")
            protected boolean matchesSafely(LogEvent item) {
                var objectMessage = (ObjectMessage) item.getMessage();

                var properties = (Map<String, String>) objectMessage.getParameter();

                return !properties.containsKey(key);
            }

            @Override
            public void describeTo(Description description) {
                description.appendText("a log event without ObjectMessage property [" + key + "]");
            }
        };
    }

    public static Matcher<LogEvent> hasContextData(String key, String value) {
        return new TypeSafeMatcher<>() {

            @Override
            @SuppressWarnings("unchecked")
            protected boolean matchesSafely(LogEvent item) {
                return item.getContextData().containsKey(key)
                        && item.getContextData().getValue(key).equals(value);
            }

            @Override
            public void describeTo(Description description) {
                description.appendText(
                        "a log event with ContextData property [" + key + ", " + value + "]");
            }
        };
    }
}
