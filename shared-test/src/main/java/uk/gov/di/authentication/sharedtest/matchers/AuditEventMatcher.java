package uk.gov.di.authentication.sharedtest.matchers;

import org.hamcrest.Description;
import org.hamcrest.TypeSafeDiagnosingMatcher;
import uk.gov.di.audit.AuditPayload;
import uk.gov.di.authentication.shared.domain.AuditableEvent;

import java.util.function.Function;

public class AuditEventMatcher<T> extends TypeSafeDiagnosingMatcher<AuditPayload.AuditEvent> {

    private final String name;
    private final Function<AuditPayload.AuditEvent, T> mapper;
    private final T expected;

    private AuditEventMatcher(
            String name, Function<AuditPayload.AuditEvent, T> mapper, T expected) {
        this.name = name;
        this.mapper = mapper;
        this.expected = expected;
    }

    public static AuditEventMatcher<AuditableEvent> hasEventType(AuditableEvent eventType) {
        Function<AuditPayload.AuditEvent, AuditableEvent> extractEventType =
                auditEvent -> eventType.parseFromName(auditEvent.getEventName());

        return new AuditEventMatcher<>("event name", extractEventType, eventType);
    }

    @Override
    protected boolean matchesSafely(
            AuditPayload.AuditEvent auditEvent, Description mismatchDescription) {
        var actual = mapper.apply(auditEvent);

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
        return "an audit event with " + name + ": " + value;
    }
}
