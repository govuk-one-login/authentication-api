package uk.gov.di.orchestration.shared.services;

import com.google.gson.annotations.Expose;
import com.google.gson.reflect.TypeToken;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.RSAKey;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

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

            assertEquals("e44ca187e5f3fee60c2d772cc9743f1175899ddc53fcc1178587a2fbd8d20081", testECKey.getKeyID());
            assertEquals("ES256", testECKey.getAlgorithm().toString());
            assertEquals(KeyType.EC, testECKey.getKeyType());
        }

        @Test
        void shouldDeserialiseRSAKeyJson() throws Exception {
            var testRSAKeyJsonString =
                    "{"
                            + "\"kty\": \"RSA\","
                            + "\"e\": \"AQAB\","
                            + "\"use\": \"sig\","
                            + "\"kid\": \"646cbe13a3af45842a4a5b6c95e9cbc96e31b8fd393f0e971d54c58863ed34f2\","
                            + "\"alg\": \"RS256\","
                            + "\"n\": \"mUCN8SxuAHLa-oEqoKACK3aSd7Vlt4X6sIsVcVpvYix6FoHDHayj4Wj3q2isW3VR8b-Ej-_7u982GEklK5APvhwTI8EzrnObfBORppdqjB_yrqPMjIdRNtPKYa1EEG-acCbKYbdDundUPHRW7CAXZjREh1nthRsDJlxkkNYyqd4JEX3EkPaH5xEavUCbPLI4a4WTf63iuycWsXNTTyvUHFN8kelBq6gGzu4PY5u7eRXoc9IXuqV0sMwJOaXwveIP6X2k2I7PdF6TWG77IOU9y5QYrGrfmDwbxEboGJ3NMaLE2eNyAQ0GOEZ64_eveSa-hEJrRR7lzZe4Ty1R2WuGE2piTAt94vxz5FHwXrWZorB7I6y6ykau20_QCVcotI6htlp8JmGw-EzHRKwh4qDeje43tgfqQ0KbPysy-miK7AaUIi_ExwRWHxaRdwq5Hu08Y8-qNwqGggHI-g5go-fPobnk_uIUjm3TKjHGg06xCCRVmBiBgbfw2wvM0O4RdlZEDAsjEGPmfU7--LvxFHLoBskNBWzjuhNbOQNi3wuAX4b8IVZaD-94DLDXGldfaIUkuOSLz9Nero17GV7qgIQaKmf_bEgk_J1ZyT1M3eLGOaJzT2FousQf9QZTuGMeQDsK64uII_OVna5PqouMjLjSePWWsVltw7ooujB5Gvj9ojs\""
                            + "}";

            var testRSAKey = serializationService.readValue(testRSAKeyJsonString, RSAKey.class);

            assertEquals("646cbe13a3af45842a4a5b6c95e9cbc96e31b8fd393f0e971d54c58863ed34f2", testRSAKey.getKeyID());
            assertEquals("RS256", testRSAKey.getAlgorithm().toString());
            assertEquals(KeyType.RSA, testRSAKey.getKeyType());
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
            ArrayList<ECKey> testECKey = serializationService.readValue(testECKeyJsonString, listType);

            assertEquals(2, testECKey.size());
            assertEquals("e44ca187e5f3fee60c2d772cc9743f1175899ddc53fcc1178587a2fbd8d20081", testECKey.get(0).getKeyID());
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
