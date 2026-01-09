package uk.gov.di.orchestration.shared.helpers;

import com.google.gson.JsonParser;
import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;

// QualityGateUnitTest
public class JsonUpdateHelperTest {

    // QualityGateRegressionTest
    @Test
    void testUpdateStringReturnsNewValue() {
        var oldJson = "\"abc\"";
        var newJson = "\"def\"";
        var expectedJson = "\"def\"";
        assertJsonEqual(JsonUpdateHelper.updateJson(oldJson, newJson), expectedJson);
    }

    // QualityGateRegressionTest
    @Test
    void testUpdateNumberReturnsNewNumber() {
        var oldJson = "123";
        var newJson = "789";
        var expectedJson = "789";
        assertJsonEqual(JsonUpdateHelper.updateJson(oldJson, newJson), expectedJson);
    }

    // QualityGateRegressionTest
    @Test
    void testUpdateBooleanReturnsNewBoolean() {
        var oldJson = "true";
        var newJson = "false";
        var expectedJson = "false";
        assertJsonEqual(JsonUpdateHelper.updateJson(oldJson, newJson), expectedJson);
    }

    // QualityGateRegressionTest
    @Test
    void testUpdateToNullReturnNull() {
        var oldJson = "true";
        var newJson = "null";
        var expectedJson = "null";
        assertJsonEqual(JsonUpdateHelper.updateJson(oldJson, newJson), expectedJson);
    }

    // QualityGateRegressionTest
    @Test
    void testUpdateFromNullReturnNewValue() {
        var oldJson = "null";
        var newJson = "[]";
        var expectedJson = "[]";
        assertJsonEqual(JsonUpdateHelper.updateJson(oldJson, newJson), expectedJson);
    }

    // QualityGateRegressionTest
    @Test
    void testUpdateVariableTypeReturnNewValue() {
        var oldJson = "[]";
        var newJson = "{}";
        var expectedJson = "{}";
        assertJsonEqual(JsonUpdateHelper.updateJson(oldJson, newJson), expectedJson);
    }

    // QualityGateRegressionTest
    @Test
    void testUpdateObjectReturnsUpdatedObject() {
        var oldJson =
                """
                {
                    "field_a": 11,
                    "field_b": 12
                }
                """;
        var newJson =
                """
                {
                    "field_a": 21,
                    "field_c": 22
                }
                """;
        var expectedJson =
                """
                {
                    "field_a": 21,
                    "field_b": 12,
                    "field_c": 22
                }
                """;
        assertJsonEqual(JsonUpdateHelper.updateJson(oldJson, newJson), expectedJson);
    }

    // QualityGateRegressionTest
    @Test
    void testUpdateArrayOfSameLengthReturnsUpdatedArray() {
        var oldJson =
                """
                [
                    {
                        "field_a": 11,
                        "field_b": 12
                    },
                    {
                        "field_a": 21,
                        "field_b": 22
                    }
                ]
                """;
        var newJson =
                """
                [
                    {
                        "field_a": 10,
                        "field_c": 13
                    },
                    {
                        "field_a": 20,
                        "field_c": 23
                    }
                ]
                """;
        var expectedJson =
                """
                [
                    {
                        "field_a": 10,
                        "field_b": 12,
                        "field_c": 13
                    },
                    {
                        "field_a": 20,
                        "field_b": 22,
                        "field_c": 23
                    }
                ]
                """;
        assertJsonEqual(JsonUpdateHelper.updateJson(oldJson, newJson), expectedJson);
    }

    // QualityGateRegressionTest
    @Test
    void testUpdateArrayOfDifferentLengthReturnsNewArray() {
        var oldJson =
                """
                [
                    {
                        "field_a": 11,
                        "field_b": 12
                    },
                    {
                        "field_a": 21,
                        "field_b": 22
                    }
                ]
                """;
        var newJson =
                """
                [
                    {
                        "field_a": 10,
                        "field_c": 13
                    }
                ]
                """;
        var expectedJson =
                """
                [
                    {
                        "field_a": 10,
                        "field_c": 13
                    }
                ]
                """;
        assertJsonEqual(JsonUpdateHelper.updateJson(oldJson, newJson), expectedJson);
    }

    // QualityGateRegressionTest
    @Test
    void testUpdateNestedReturnsCorrectValue() {
        var oldJson =
                """
                {
                    "field_a":
                    {
                        "nested_field_a": "StringValue1",
                        "nested_field_b": 1
                    },
                    "field_b":
                    {
                        "nested_field_a": "StringValue2",
                        "nested_field_b": 2
                    },
                    "field_c": [
                        {
                            "nested_field_a": "StringValue3",
                            "nested_field_b": 3
                        },
                        {
                            "nested_field_a": "StringValue4",
                            "nested_field_b": 4
                        }
                    ],
                    "field_d": [
                        {
                            "nested_field_a": "StringValue5",
                            "nested_field_b": 5
                        }
                    ]
                }
                """;
        var newJson =
                """
                {
                    "field_a":
                    {
                        "nested_field_b": null,
                        "nested_field_c": true
                    },
                    "field_e":
                    {
                        "nested_field_b": 2,
                        "nested_field_c": true
                    },
                    "field_c": [
                        {
                            "nested_field_b": 300,
                            "nested_field_c": true
                        },
                        {
                            "nested_field_b": 400,
                            "nested_field_c": false
                        }
                    ],
                    "field_d": [
                        {
                            "nested_field_b": 500,
                            "nested_field_c": false
                        },
                        {
                            "nested_field_b": 600,
                            "nested_field_c": true
                        }
                    ]
                }
                """;
        var expectedJson =
                """
                {
                    "field_a":
                    {
                        "nested_field_a": "StringValue1",
                        "nested_field_b": null,
                        "nested_field_c": true
                    },
                    "field_b":
                    {
                        "nested_field_a": "StringValue2",
                        "nested_field_b": 2
                    },
                    "field_e":
                    {
                        "nested_field_b": 2,
                        "nested_field_c": true
                    },
                    "field_c": [
                        {
                            "nested_field_a": "StringValue3",
                            "nested_field_b": 300,
                            "nested_field_c": true
                        },
                        {
                            "nested_field_a": "StringValue4",
                            "nested_field_b": 400,
                            "nested_field_c": false
                        }
                    ],
                    "field_d": [
                        {
                            "nested_field_b": 500,
                            "nested_field_c": false
                        },
                        {
                            "nested_field_b": 600,
                            "nested_field_c": true
                        }
                    ]
                }
                """;
        assertJsonEqual(JsonUpdateHelper.updateJson(oldJson, newJson), expectedJson);
    }

    public void assertJsonEqual(String jsonA, String jsonB) {
        assertThat(JsonParser.parseString(jsonA), is(equalTo(JsonParser.parseString(jsonB))));
    }
}
