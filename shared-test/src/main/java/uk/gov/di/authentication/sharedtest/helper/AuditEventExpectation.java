package uk.gov.di.authentication.sharedtest.helper;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.opentest4j.AssertionFailedError;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class AuditEventExpectation {
    private final String eventName;
    private final Map<String, Object> expectedAttributes;

    public AuditEventExpectation(String eventName) {
        this.eventName = eventName;
        this.expectedAttributes = new HashMap<>();
    }

    public AuditEventExpectation withAttribute(String key, Object value) {
        expectedAttributes.put(key, value);
        return this;
    }

    public void verify(List<String> receivedEvents) {
        String event = findEventByName(receivedEvents, eventName);
        var jsonEvent = JsonParser.parseString(event).getAsJsonObject();

        for (Map.Entry<String, Object> entry : expectedAttributes.entrySet()) {
            String path = entry.getKey();
            Object expectedValue = entry.getValue();

            JsonElement actualElement = getJsonElementByPath(jsonEvent, path);
            if (expectedValue instanceof String) {
                assertEquals(
                        expectedValue,
                        actualElement.getAsString(),
                        "Attribute " + path + " in event " + eventName);
            } else if (expectedValue instanceof Boolean) {
                assertEquals(
                        expectedValue,
                        actualElement.getAsBoolean(),
                        "Attribute " + path + " in event " + eventName);
            } else if (expectedValue instanceof Number) {
                assertEquals(
                        ((Number) expectedValue).doubleValue(),
                        actualElement.getAsDouble(),
                        "Attribute " + path + " in event " + eventName);
            }
        }
    }

    private String findEventByName(List<String> events, String name) {
        return events.stream()
                .filter(
                        event -> {
                            var jsonObj = JsonParser.parseString(event).getAsJsonObject();
                            return jsonObj.get("event_name").getAsString().equalsIgnoreCase(name);
                        })
                .findFirst()
                .orElseThrow(() -> new AssertionFailedError("Missing " + name + " audit event."));
    }

    private JsonElement getJsonElementByPath(JsonObject json, String path) {
        String[] parts = path.split("\\.");
        JsonElement current = json;

        for (String part : parts) {
            if (current.isJsonObject()) {
                current = current.getAsJsonObject().get(part);
                if (current == null) {
                    throw new AssertionFailedError("Path " + path + " not found in event");
                }
            } else {
                throw new AssertionFailedError("Cannot navigate path " + path + " in event");
            }
        }

        return current;
    }
}
