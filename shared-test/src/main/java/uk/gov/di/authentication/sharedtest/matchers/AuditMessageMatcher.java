package uk.gov.di.authentication.sharedtest.matchers;

import org.hamcrest.Description;
import org.hamcrest.TypeSafeDiagnosingMatcher;
import uk.gov.di.audit.AuditPayload.AuditEvent;
import uk.gov.di.audit.AuditPayload.SignedAuditEvent;
import uk.gov.di.authentication.shared.services.AuditService.MetadataPair;

import java.util.Base64;
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

    public static AuditMessageMatcher<String> hasClientId(String clientId) {
        return new AuditMessageMatcher<>("client ID", AuditEvent::getClientId, clientId);
    }

    public static AuditMessageMatcher<String> hasSubjectId(String subjectId) {
        Function<AuditEvent, String> getSubjectId = (auditEvent) -> auditEvent.getUser().getId();
        return new AuditMessageMatcher<>("subject ID", getSubjectId, subjectId);
    }

    public static AuditMessageMatcher<String> hasEmail(String email) {
        Function<AuditEvent, String> getEmail = (auditEvent) -> auditEvent.getUser().getEmail();
        return new AuditMessageMatcher<>("email", getEmail, email);
    }

    public static AuditMessageMatcher<String> hasIpAddress(String ipAddress) {
        Function<AuditEvent, String> getIpAddress =
                (auditEvent) -> auditEvent.getUser().getIpAddress();
        return new AuditMessageMatcher<>("ip address", getIpAddress, ipAddress);
    }

    public static AuditMessageMatcher<String> hasPhoneNumber(String phoneNumber) {
        Function<AuditEvent, String> getPhoneNumber =
                (auditEvent) -> auditEvent.getUser().getPhoneNumber();
        return new AuditMessageMatcher<>("phone number", getPhoneNumber, phoneNumber);
    }

    public static AuditMessageMatcher<String> hasMetadataPair(MetadataPair metadataPair) {
        Function<AuditEvent, String> getValue =
                (auditEvent) -> auditEvent.getExtensionsOrThrow(metadataPair.getKey());
        return new AuditMessageMatcher<>(
                String.format("metadata value for key '%s'", metadataPair.getKey()),
                getValue,
                metadataPair.getValue().toString());
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
                    SignedAuditEvent.parseFrom(Base64.getDecoder().decode(serialisedMessage));

            return AuditEvent.parseFrom(signedAuditEvent.getPayload());
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }
}
