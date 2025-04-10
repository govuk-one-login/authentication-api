package uk.gov.di.orchestration.sharedtest.logging;

import org.apache.logging.log4j.core.LogEvent;
import org.hamcrest.Description;
import org.hamcrest.Matcher;
import org.hamcrest.TypeSafeMatcher;

import java.util.Arrays;

public class LogEventMatcher {

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

    public static Matcher<LogEvent> withMessageContaining(String... values) {
        return new TypeSafeMatcher<>() {

            @Override
            protected boolean matchesSafely(LogEvent item) {
                var message = item.getMessage().getFormattedMessage();

                return Arrays.stream(values).anyMatch(message::contains);
            }

            @Override
            public void describeTo(Description description) {
                description.appendText(
                        "a log event with message containing [" + Arrays.asList(values) + "]");
            }
        };
    }

    public static Matcher<LogEvent> withThrownMessageContaining(String... values) {
        return new TypeSafeMatcher<>() {

            @Override
            protected boolean matchesSafely(LogEvent item) {
                if (item.getThrown() == null) {
                    return false;
                }
                var message = item.getThrown().getMessage();
                return Arrays.stream(values).anyMatch(message::contains);
            }

            @Override
            public void describeTo(Description description) {
                description.appendText(
                        "a log event with throwable message containing ["
                                + Arrays.asList(values)
                                + "]");
            }
        };
    }

    public static Matcher<LogEvent> withMessage(String value) {
        return new TypeSafeMatcher<>() {

            @Override
            protected boolean matchesSafely(LogEvent item) {
                var message = item.getMessage().getFormattedMessage();

                return value.equals(message);
            }

            @Override
            public void describeTo(Description description) {
                description.appendText("a log event with message [" + value + "]");
            }
        };
    }
}
