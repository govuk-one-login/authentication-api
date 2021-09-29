package uk.gov.di.authentication.shared.matchers;

import org.hamcrest.Description;
import org.hamcrest.TypeSafeDiagnosingMatcher;
import uk.gov.di.audit.AuditPayload;

import java.nio.charset.StandardCharsets;
import java.util.function.Function;

public class AuditMessageMatcher<T> extends TypeSafeDiagnosingMatcher<String> {

    private final String name;
    private final Function<String, T> mapper;
    private final T expected;

    private AuditMessageMatcher(
            String name, Function<AuditPayload.AuditEvent, T> mapper, T expected) {
        this.name = name;
        this.expected = expected;

        Function<String, AuditPayload.AuditEvent>
                annoyingInterimVariableBecauseFPIsANightmareInJava = this::deserialiseAuditEvent;
        this.mapper = annoyingInterimVariableBecauseFPIsANightmareInJava.andThen(mapper);
    }

    public static AuditMessageMatcher<String> hasEventName(String eventName) {
        return new AuditMessageMatcher<>(
                "event name", AuditPayload.AuditEvent::getEventName, eventName);
    }

    public static AuditMessageMatcher<String> hasTimestamp(String timestampAsString) {
        return new AuditMessageMatcher<>(
                "timestamp", AuditPayload.AuditEvent::getTimestamp, timestampAsString);
    }

    @Override
    protected boolean matchesSafely(
            String serialisedAuditMessage, Description mismatchDescription) {
        var actual = mapper.apply(serialisedAuditMessage);

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
        return "an audit message with " + name + ": " + value;
    }

    private AuditPayload.AuditEvent deserialiseAuditEvent(String serialisedMessage) {
        try {
            var signedAuditEvent =
                    AuditPayload.SignedAuditEvent.parseFrom(
                            serialisedMessage.getBytes(StandardCharsets.UTF_8));

            return AuditPayload.AuditEvent.parseFrom(signedAuditEvent.getPayload());
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }
}
