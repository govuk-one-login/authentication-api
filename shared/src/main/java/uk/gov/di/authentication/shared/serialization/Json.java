package uk.gov.di.authentication.shared.serialization;

import com.fasterxml.jackson.core.JsonProcessingException;
import uk.gov.di.authentication.shared.helpers.ObjectMapperFactory;

public interface Json {
    <T> T readValue(String body, Class<T> klass) throws JsonException;

    String writeValueAsString(Object object) throws JsonException;

    class JsonException extends Exception {
        public JsonException(Exception e) {
            super(e);
        }
    }

    static Json jackson() {
        return new Json() {
            @Override
            public <T> T readValue(String body, Class<T> klass) throws JsonException {
                try {
                    return ObjectMapperFactory.getInstance().readValue(body, klass);
                } catch (JsonProcessingException e) {
                    throw new JsonException(e);
                }
            }

            @Override
            public String writeValueAsString(Object object) throws JsonException {
                try {
                    return ObjectMapperFactory.getInstance().writeValueAsString(object);
                } catch (JsonProcessingException e) {
                    throw new JsonException(e);
                }
            }
        };
    }
}
