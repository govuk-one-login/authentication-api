package uk.gov.di.orchestration.shared.serialization;

import uk.gov.di.orchestration.shared.validation.Validator;

import java.lang.reflect.Type;

public interface Json {
    <T> T readValueUnchecked(String jsonString, Class<T> clazz);

    <T> T readValue(String body, Class<T> klass) throws JsonException;

    <T> T readValue(String body, Type typeOfT) throws JsonException;

    <T> T readValue(String body, Class<T> klass, Validator validator) throws JsonException;

    <T> T readValue(String body, Type typeOfT, Validator validator) throws JsonException;

    String writeValueAsString(Object object) throws JsonException;

    class JsonException extends Exception {
        public JsonException(Exception e) {
            super(e);
        }

        public JsonException(String message) {
            super(message);
        }
    }
}
