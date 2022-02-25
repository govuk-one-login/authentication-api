package uk.gov.di.accountmanagement.testsupport.matchers;

import org.hamcrest.Description;
import org.hamcrest.TypeSafeDiagnosingMatcher;
import uk.gov.di.accountmanagement.entity.NotificationType;
import uk.gov.di.accountmanagement.entity.NotifyRequest;

import java.util.function.Function;

public class NotifyRequestMatcher<T> extends TypeSafeDiagnosingMatcher<NotifyRequest> {

    private final String name;
    private final Function<NotifyRequest, T> mapper;
    private final T expected;

    private NotifyRequestMatcher(String name, Function<NotifyRequest, T> mapper, T expected) {
        this.name = name;
        this.mapper = mapper;
        this.expected = expected;
    }

    public static NotifyRequestMatcher<String> hasDestination(String destination) {
        Function<NotifyRequest, String> extractDestination = NotifyRequest::getDestination;

        return new NotifyRequestMatcher<>("destination", extractDestination, destination);
    }

    public static NotifyRequestMatcher<NotificationType> hasNotificationType(
            NotificationType notificationType) {
        Function<NotifyRequest, NotificationType> extractNotificationType =
                NotifyRequest::getNotificationType;

        return new NotifyRequestMatcher<>(
                "notification type", extractNotificationType, notificationType);
    }

    @Override
    protected boolean matchesSafely(NotifyRequest notifyRequest, Description mismatchDescription) {
        var actual = mapper.apply(notifyRequest);

        boolean matched = actual.equals(expected);

        if (!matched) {
            mismatchDescription.appendText(description(actual));
        }

        return matched;
    }

    @Override
    public void describeTo(Description description) {
        description.appendText(description(expected));
    }

    private String description(T value) {
        return "a notification with " + name + ": " + value;
    }
}
