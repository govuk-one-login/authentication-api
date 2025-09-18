package uk.gov.di.authentication.sharedtest.helper;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.opentest4j.AssertionFailedError;
import uk.gov.di.authentication.shared.domain.AuditableEvent;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class AuditEventExpectation {
    private final AuditableEvent event;
    private final Map<String, Object> expectedAttributes;

    public AuditEventExpectation(AuditableEvent event) {
        this.event = event;
        this.expectedAttributes = new HashMap<>();
    }

    public AuditEventExpectation(AuditEventExpectation expectation) {
        this.event = expectation.event;
        this.expectedAttributes = expectation.expectedAttributes;
    }

    public AuditableEvent getEvent() {
        return event;
    }

    private String getEventName() {
        return event.toString();
    }

    public AuditEventExpectation withAttribute(String key, Object value) {
        expectedAttributes.put(key, value);
        return this;
    }

    public void verify(List<String> receivedEvents) {
        for (String event : receivedEvents) {
            var jsonEvent = JsonParser.parseString(event).getAsJsonObject();

            if (!jsonEvent.get("event_name").getAsString().equalsIgnoreCase(this.getEventName())) {
                continue;
            }

            boolean allAttributesMatch = true;
            for (Map.Entry<String, Object> entry : expectedAttributes.entrySet()) {
                String path = entry.getKey();
                Object expectedValue = entry.getValue();

                JsonElement actualElement = getJsonElementByPath(jsonEvent, path);
                if (actualElement == null) {
                    allAttributesMatch = false;
                    break;
                }

                boolean matches = false;
                if (expectedValue instanceof String && actualElement.isJsonPrimitive()) {
                    matches = expectedValue.equals(actualElement.getAsString());
                } else if (expectedValue instanceof Boolean && actualElement.isJsonPrimitive()) {
                    matches = expectedValue.equals(actualElement.getAsBoolean());
                } else if (expectedValue instanceof Number number
                        && actualElement.isJsonPrimitive()) {
                    matches = number.doubleValue() == actualElement.getAsDouble();
                }

                if (!matches) {
                    allAttributesMatch = false;
                    break;
                }
            }

            if (allAttributesMatch) {
                return;
            }
        }

        throw new AssertionFailedError(
                "No matching audit event found for "
                        + this.getEventName()
                        + " with expected attributes: "
                        + expectedAttributes);
    }

    private JsonElement getJsonElementByPath(JsonObject json, String path) {
        String[] parts = path.split("\\.");
        JsonElement current = json;

        for (String part : parts) {
            if (current.isJsonObject()) {
                current = current.getAsJsonObject().get(part);
                if (current == null) {
                    throw new AssertionFailedError(
                            "Path " + path + " not found in event " + this.getEventName());
                }
            } else {
                throw new AssertionFailedError(
                        "Cannot navigate path " + path + " in event " + this.getEventName());
            }
        }

        return current;
    }
}
