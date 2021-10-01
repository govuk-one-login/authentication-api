package uk.gov.di.authentication.shared.matchers;

import org.hamcrest.Description;
import org.hamcrest.TypeSafeDiagnosingMatcher;
import uk.gov.di.audit.AuditPayload.AuditEvent;
import uk.gov.di.audit.AuditPayload.SignedAuditEvent;

import java.nio.charset.StandardCharsets;
import java.util.function.Function;

public class AuditMessageMatcher<T> extends TypeSafeDiagnosingMatcher<String> {

    private final String name;
    private final Function<String, T> mapper;
    private final T expected;

    private AuditMessageMatcher(String name, Function<AuditEvent, T> mapper, T expected) {
        this.name = name;
        this.mapper = input -> mapper.apply(deserialiseAuditEvent(input));
        this.expected = expected;
    }

    public static AuditMessageMatcher<String> hasEventName(String eventName) {
        return new AuditMessageMatcher<>("event name", AuditEvent::getEventName, eventName);
    }

    public static AuditMessageMatcher<String> hasTimestamp(String timestampAsString) {
        return new AuditMessageMatcher<>("timestamp", AuditEvent::getTimestamp, timestampAsString);
    }

    public static AuditMessageMatcher<String> hasRequestId(String requestId) {
        return new AuditMessageMatcher<>("request ID", AuditEvent::getRequestId, requestId);
    }

    public static AuditMessageMatcher<String> hasSessionId(String sessionId) {
        return new AuditMessageMatcher<>("session ID", AuditEvent::getSessionId, sessionId);
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

    private AuditEvent deserialiseAuditEvent(String serialisedMessage) {
        try {
            var signedAuditEvent =
                    SignedAuditEvent.parseFrom(serialisedMessage.getBytes(StandardCharsets.UTF_8));

            return AuditEvent.parseFrom(signedAuditEvent.getPayload());
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }
}
