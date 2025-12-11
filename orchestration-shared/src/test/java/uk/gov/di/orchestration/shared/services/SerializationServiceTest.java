package uk.gov.di.orchestration.shared.services;

import com.google.gson.annotations.Expose;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

// QualityGateUnitTest
class SerializationServiceTest {
    private final SerializationService serializationService = SerializationService.getInstance();

    @Nested
    class Deserialise {
        // QualityGateRegressionTest
        @Test
        void shouldDeserialiseJsonStringWithAllFields() throws Exception {
            var testJsonString =
                    "{"
                            + "\"string_field\":\"abc\", "
                            + "\"int_field\":123, "
                            + "\"string_list_field\":[\"def\", \"ghi\"]"
                            + "}";

            var testObject = serializationService.readValue(testJsonString, TestObject.class);

            assertEquals("abc", testObject.stringField);
            assertEquals(123, testObject.intField);
            assertEquals(List.of("def", "ghi"), testObject.stringListField);
        }

        // QualityGateRegressionTest
        @Test
        void shouldDeserialiseJsonStringWithMissingFields() throws Exception {
            var testJsonString = "{\"int_field\":123, \"string_list_field\":[\"def\", \"ghi\"]}";

            var testObject = serializationService.readValue(testJsonString, TestObject.class);

            assertNull(testObject.stringField);
            assertEquals(123, testObject.intField);
            assertEquals(List.of("def", "ghi"), testObject.stringListField);
        }

        // QualityGateRegressionTest
        @Test
        void shouldDeserialiseJsonStringWithExtraFields() throws Exception {
            var testJsonString =
                    "{"
                            + "\"string_field\":\"abc\", "
                            + "\"int_field\":123, "
                            + "\"string_list_field\":[\"def\", \"ghi\"],"
                            + "\"extra_field_1\": \"test1\","
                            + "\"extra_field_2\": \"test2\""
                            + "}";

            var testObject = serializationService.readValue(testJsonString, TestObject.class);

            assertEquals("abc", testObject.stringField);
            assertEquals(123, testObject.intField);
            assertEquals(List.of("def", "ghi"), testObject.stringListField);
        }
    }

    @Nested
    class Serialise {
        // QualityGateRegressionTest
        @Test
        void shouldSerialiseObjectWithAllFields() {
            var testObject = new TestObject("abc", 123, List.of("def", "ghi"));

            var actualJsonString = serializationService.writeValueAsString(testObject);
            var expectedJsonString =
                    "{"
                            + "\"string_field\":\"abc\","
                            + "\"int_field\":123,"
                            + "\"string_list_field\":[\"def\",\"ghi\"]"
                            + "}";
            assertEquals(expectedJsonString, actualJsonString);
        }

        // QualityGateRegressionTest
        @Test
        void shouldSerialiseObjectWithNullFieldToJsonString() {
            var testObject = new TestObject(null, 123, List.of("def", "ghi"));

            var actualJsonString = serializationService.writeValueAsString(testObject);
            var expectedJsonString =
                    "{"
                            + "\"string_field\":null,"
                            + "\"int_field\":123,"
                            + "\"string_list_field\":[\"def\",\"ghi\"]"
                            + "}";
            assertEquals(expectedJsonString, actualJsonString);
        }
    }

    private static class TestObject {
        @Expose private String stringField;
        @Expose private int intField;
        @Expose private List<String> stringListField;

        public TestObject(String stringField, int intField, List<String> stringListField) {
            this.stringField = stringField;
            this.intField = intField;
            this.stringListField = stringListField;
        }
    }
}
