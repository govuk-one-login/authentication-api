package uk.gov.di.authentication.shared.converters;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ObjectConverterTest {

    private ObjectConverter objectConverter;

    @BeforeEach
    void setUp() {
        objectConverter = new ObjectConverter();
    }

    @Test
    void shouldTransformFromObjectToAttributeValue() {
        Map<String, Object> testObject = Map.of("key", "value", "number", 123);

        AttributeValue result = objectConverter.transformFrom(testObject);

        String jsonString = result.s();
        assertTrue(jsonString.contains("\"key\":\"value\""));
        assertTrue(jsonString.contains("\"number\":123"));
    }

    @Test
    void shouldTransformFromNullToNullAttributeValue() {
        AttributeValue result = objectConverter.transformFrom(null);

        assertTrue(result.nul());
    }

    @Test
    void shouldTransformToObjectFromAttributeValue() {
        AttributeValue attributeValue =
                AttributeValue.builder().s("{\"key\":\"value\",\"number\":123}").build();

        Object result = objectConverter.transformTo(attributeValue);

        assertTrue(result instanceof Map);
        @SuppressWarnings("unchecked")
        Map<String, Object> resultMap = (Map<String, Object>) result;
        assertEquals("value", resultMap.get("key"));
        assertEquals(123.0, resultMap.get("number"));
    }

    @Test
    void shouldTransformToNullFromNullAttributeValue() {
        AttributeValue attributeValue = AttributeValue.builder().nul(true).build();

        Object result = objectConverter.transformTo(attributeValue);

        assertNull(result);
    }

    @Test
    void shouldThrowRuntimeExceptionForInvalidJson() {
        AttributeValue attributeValue = AttributeValue.builder().s("invalid json").build();

        assertThrows(RuntimeException.class, () -> objectConverter.transformTo(attributeValue));
    }
}
