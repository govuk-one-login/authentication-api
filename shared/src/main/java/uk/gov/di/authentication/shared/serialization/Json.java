package uk.gov.di.authentication.shared.serialization;

import uk.gov.di.authentication.shared.helpers.ObjectMapperFactory;

import static uk.gov.di.authentication.shared.helpers.InstrumentationHelper.segmentedFunctionCall;

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
                    return segmentedFunctionCall(
                            "Jackson::ObjectMapper::readValue",
                            () -> ObjectMapperFactory.getInstance().readValue(body, klass));
                } catch (Exception e) {
                    throw new JsonException(e);
                }
            }

            @Override
            public String writeValueAsString(Object object) throws JsonException {
                try {
                    return segmentedFunctionCall(
                            "Jackson::ObjectMapper::writeValueAsString",
                            () -> ObjectMapperFactory.getInstance().writeValueAsString(object));
                } catch (Exception e) {
                    throw new JsonException(e);
                }
            }
        };
    }
}
