package uk.gov.di.authentication.shared.services;

import com.google.gson.FieldNamingPolicy;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import jakarta.validation.ConstraintViolationException;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.shared.serialization.Json;

import static java.util.Objects.isNull;
import static uk.gov.di.authentication.shared.helpers.InstrumentationHelper.segmentedFunctionCall;

public class SerializationService implements Json {

    private static SerializationService INSTANCE;
    private static Logger LOG = LogManager.getLogger(SerializationService.class);

    private final Gson gson;
    private final Validator validator;

    public SerializationService() {
        gson =
                new GsonBuilder()
                        .setFieldNamingPolicy(FieldNamingPolicy.LOWER_CASE_WITH_UNDERSCORES)
                        .serializeNulls()
                        .excludeFieldsWithoutExposeAnnotation()
                        .create();

        validator = Validation.buildDefaultValidatorFactory().getValidator();
    }

    @Override
    public <T> T readValue(String jsonString, Class<T> clazz) throws JsonException {
        T value =
                segmentedFunctionCall(
                        "SerializationService::GSON::fromJson",
                        () -> gson.fromJson(jsonString, clazz));
        var violations =
                segmentedFunctionCall(
                        "SerializationService::validator::validate",
                        () -> validator.validate(value));
        if (violations.isEmpty()) {
            return value;
        }
        violations.forEach(v -> LOG.warn("Json validation violation: {}", v.getMessage()));
        throw new JsonException(
                new ConstraintViolationException("JSON validation error", violations));
    }

    @Override
    public String writeValueAsString(Object object) {
        return segmentedFunctionCall(
                "SerializationService::GSON::toJson", () -> gson.toJson(object));
    }

    public static SerializationService getInstance() {
        if (isNull(INSTANCE)) {
            INSTANCE = new SerializationService();
        }
        return INSTANCE;
    }
}
