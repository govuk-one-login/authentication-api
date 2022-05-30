package uk.gov.di.authentication.shared.serialization;

import uk.gov.di.authentication.shared.validation.Validator;

public interface Json {
    <T> T readValue(String body, Class<T> klass) throws JsonException;

    <T> T readValue(String body, Class<T> klass, Validator validator) throws JsonException;

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
