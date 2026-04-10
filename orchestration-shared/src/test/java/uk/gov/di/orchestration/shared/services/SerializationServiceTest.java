package uk.gov.di.orchestration.shared.services;

import com.google.gson.annotations.Expose;
import com.google.gson.reflect.TypeToken;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static java.lang.String.format;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SerializationServiceTest {
    private final SerializationService serializationService = SerializationService.getInstance();

    @Nested
    class Deserialise {
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

        @Test
        void shouldDeserialiseJsonStringWithMissingFields() throws Exception {
            var testJsonString = "{\"int_field\":123, \"string_list_field\":[\"def\", \"ghi\"]}";

            var testObject = serializationService.readValue(testJsonString, TestObject.class);

            assertNull(testObject.stringField);
            assertEquals(123, testObject.intField);
            assertEquals(List.of("def", "ghi"), testObject.stringListField);
        }

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

        @Test
        void shouldDeserialiseECKeyJson() throws Exception {
            var testECKeyJsonString =
                    "{"
                            + "\"kty\": \"EC\","
                            + "\"use\": \"sig\","
                            + "\"crv\": \"P-256\","
                            + "\"kid\": \"e44ca187e5f3fee60c2d772cc9743f1175899ddc53fcc1178587a2fbd8d20081\","
                            + "\"x\": \"ccziorFA2LGN3Jdd8pAQNNLjYkTM5DqD2bXiHb62HF4\","
                            + "\"y\": \"nd02oQv8Uz9mjy3-EUG6nzuzdhW4TwYh6RA94n8RAJc\","
                            + "\"alg\": \"ES256\""
                            + "}";

            var testECKey = serializationService.readValue(testECKeyJsonString, ECKey.class);

            assertEquals(
                    "e44ca187e5f3fee60c2d772cc9743f1175899ddc53fcc1178587a2fbd8d20081",
                    testECKey.getKeyID());
            assertEquals("ES256", testECKey.getAlgorithm().toString());
            assertEquals(KeyType.EC, testECKey.getKeyType());
        }

        @Test
        void shouldDeserialiseECKeyJsonArray() throws Exception {
            var testECKeyJsonString =
                    "[{"
                            + "\"kty\": \"EC\","
                            + "\"use\": \"sig\","
                            + "\"crv\": \"P-256\","
                            + "\"kid\": \"e44ca187e5f3fee60c2d772cc9743f1175899ddc53fcc1178587a2fbd8d20081\","
                            + "\"x\": \"ccziorFA2LGN3Jdd8pAQNNLjYkTM5DqD2bXiHb62HF4\","
                            + "\"y\": \"nd02oQv8Uz9mjy3-EUG6nzuzdhW4TwYh6RA94n8RAJc\","
                            + "\"alg\": \"ES256\""
                            + "},"
                            + "{"
                            + "\"kty\": \"EC\","
                            + "\"use\": \"sig\","
                            + "\"crv\": \"P-256\","
                            + "\"kid\": \"e44ca187e5f3fee60c2d772cc9743f1175899ddc53fcc1178587a2fbd8d20081\","
                            + "\"x\": \"ccziorFA2LGN3Jdd8pAQNNLjYkTM5DqD2bXiHb62HF4\","
                            + "\"y\": \"nd02oQv8Uz9mjy3-EUG6nzuzdhW4TwYh6RA94n8RAJc\","
                            + "\"alg\": \"ES256\""
                            + "}]";

            Type listType = new TypeToken<ArrayList<ECKey>>() {}.getType();
            ArrayList<ECKey> testECKey =
                    serializationService.readValue(testECKeyJsonString, listType);

            assertEquals(2, testECKey.size());
            assertEquals(
                    "e44ca187e5f3fee60c2d772cc9743f1175899ddc53fcc1178587a2fbd8d20081",
                    testECKey.get(0).getKeyID());
            assertEquals("ES256", testECKey.get(0).getAlgorithm().toString());
            assertEquals(KeyType.EC, testECKey.get(0).getKeyType());
        }
    }

    @Nested
    class Serialise {
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

        @Test
        void shouldSerialiseECKeyJson() throws Exception {
            var testECKey =
                    new ECKeyGenerator(Curve.P_256)
                            .keyID("testid123456789")
                            .algorithm(JWSAlgorithm.ES256)
                            .generate();

            var testECKeyJsonString = serializationService.writeValueAsString(testECKey);

            assertTrue(testECKeyJsonString.contains("\"kty\":\"EC\""));
            assertTrue(testECKeyJsonString.contains("\"kid\":\"testid123456789\""));
            assertTrue(testECKeyJsonString.contains("\"alg\":\"ES256\""));
            assertTrue(testECKeyJsonString.contains("\"crv\":\"P-256\""));
            assertTrue(
                    testECKeyJsonString.contains(
                            format("\"x\":\"%s\"", testECKey.getX().toString())));
            assertTrue(
                    testECKeyJsonString.contains(
                            format("\"y\":\"%s\"", testECKey.getY().toString())));
        }

        @Test
        void shouldSerialiseECKeyJsonArray() throws Exception {
            var testECKey1 =
                    new ECKeyGenerator(Curve.P_256)
                            .keyID("testid123456789")
                            .algorithm(JWSAlgorithm.ES256)
                            .generate();
            var testECKey2 =
                    new ECKeyGenerator(Curve.P_256)
                            .keyID("testid987654321")
                            .algorithm(JWSAlgorithm.ES256)
                            .generate();

            var testECKeyJsonString =
                    serializationService.writeValueAsString(Arrays.asList(testECKey1, testECKey2));

            assertTrue(testECKeyJsonString.contains("\"kty\":\"EC\""));
            assertTrue(testECKeyJsonString.contains("\"kid\":\"testid123456789\""));
            assertTrue(testECKeyJsonString.contains("\"alg\":\"ES256\""));
            assertTrue(testECKeyJsonString.contains("\"crv\":\"P-256\""));
            assertTrue(
                    testECKeyJsonString.contains(
                            format("\"x\":\"%s\"", testECKey1.getX().toString())));
            assertTrue(
                    testECKeyJsonString.contains(
                            format("\"y\":\"%s\"", testECKey1.getY().toString())));

            assertTrue(testECKeyJsonString.contains("\"kid\":\"testid987654321\""));
            assertTrue(
                    testECKeyJsonString.contains(
                            format("\"x\":\"%s\"", testECKey2.getX().toString())));
            assertTrue(
                    testECKeyJsonString.contains(
                            format("\"y\":\"%s\"", testECKey2.getY().toString())));
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
