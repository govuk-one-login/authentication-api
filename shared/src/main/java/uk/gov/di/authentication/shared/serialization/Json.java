package uk.gov.di.authentication.shared.serialization;

public interface Json {
    <T> T readValue(String body, Class<T> klass) throws JsonException;

    String writeValueAsString(Object object) throws JsonException;

    class JsonException extends Exception {
        public JsonException(Exception e) {
            super(e);
        }
    }
}
