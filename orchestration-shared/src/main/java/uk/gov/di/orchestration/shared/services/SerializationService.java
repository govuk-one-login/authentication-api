package uk.gov.di.orchestration.shared.services;

import com.google.gson.FieldNamingPolicy;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonSyntaxException;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.orchestration.shared.annotations.Instrumented;
import uk.gov.di.orchestration.shared.serialization.Json;
import uk.gov.di.orchestration.shared.serialization.LocalDateTimeAdapter;
import uk.gov.di.orchestration.shared.serialization.StateAdapter;
import uk.gov.di.orchestration.shared.serialization.SubjectAdapter;
import uk.gov.di.orchestration.shared.validation.RequiredFieldValidator;
import uk.gov.di.orchestration.shared.validation.Validator;

import java.time.LocalDateTime;

import static java.util.Objects.isNull;

public class SerializationService implements Json {

    private static SerializationService INSTANCE;
    private static final Logger LOG = LogManager.getLogger(SerializationService.class);

    private final Gson gson;
    private final RequiredFieldValidator defaultValidator = new RequiredFieldValidator();

    public SerializationService() {
        gson =
                new GsonBuilder()
                        .setFieldNamingPolicy(FieldNamingPolicy.LOWER_CASE_WITH_UNDERSCORES)
                        .serializeNulls()
                        .excludeFieldsWithoutExposeAnnotation()
                        .registerTypeAdapter(State.class, new StateAdapter())
                        .registerTypeAdapter(LocalDateTime.class, new LocalDateTimeAdapter())
                        .registerTypeAdapter(Subject.class, new SubjectAdapter())
                        .create();
    }

    @Override
    public <T> T readValueUnchecked(String jsonString, Class<T> clazz) {
        try {
            return readValue(jsonString, clazz);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public <T> T readValue(String body, Class<T> klass) throws JsonException {
        return readValue(body, klass, defaultValidator);
    }

    @Override
    public <T> T readValue(String jsonString, Class<T> clazz, Validator validator)
            throws JsonException {
        try {
            T value = gson.fromJson(jsonString, clazz);
            validateJson(value, validator);
            return value;
        } catch (JsonSyntaxException | IllegalArgumentException e) {
            LOG.error("Error during JSON deserialization", e);
            throw new JsonException(e);
        }
    }

    @Instrumented("SerializationService::GSON::fromJson")
    private <T> T deserializeJson(String jsonString, Class<T> clazz, Validator validator, Gson gson)
            throws JsonException {
        try {
            T value = gson.fromJson(jsonString, clazz);
            validateJson(value, validator);
            return value;
        } catch (JsonSyntaxException | IllegalArgumentException e) {
            LOG.error("Error during JSON deserialization", e);
            throw new JsonException(e);
        }
    }

    @Instrumented("SerializationService::validator::validate")
    private <T> void validateJson(T value, Validator validator) throws JsonException {
        var violations = validator.validate(value);
        if (!violations.isEmpty()) {
            String violationMessage =
                    "JSON validation error, missing required field(s): "
                            + String.join(", ", violations);
            violations.forEach(
                    v -> LOG.warn("Json validation failed due to missing required field: {}", v));
            throw new JsonException(violationMessage);
        }
    }

    @Override
    @Instrumented("SerializationService::GSON::toJson")
    public String writeValueAsString(Object object) {
        return gson.toJson(object);
    }

    public static SerializationService getInstance() {
        if (isNull(INSTANCE)) {
            INSTANCE = new SerializationService();
        }
        return INSTANCE;
    }
}
