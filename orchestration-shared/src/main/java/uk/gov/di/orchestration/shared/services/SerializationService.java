package uk.gov.di.orchestration.shared.services;

import com.google.gson.FieldNamingPolicy;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonSyntaxException;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.orchestration.shared.serialization.Json;
import uk.gov.di.orchestration.shared.serialization.LocalDateTimeAdapter;
import uk.gov.di.orchestration.shared.serialization.StateAdapter;
import uk.gov.di.orchestration.shared.serialization.SubjectAdapter;
import uk.gov.di.orchestration.shared.validation.RequiredFieldValidator;
import uk.gov.di.orchestration.shared.validation.Validator;

import java.time.LocalDateTime;

import static java.util.Objects.isNull;
import static uk.gov.di.orchestration.shared.helpers.InstrumentationHelper.segmentedFunctionCall;

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
            T value = segmentedFunctionCall(() -> gson.fromJson(jsonString, clazz));
            var violations = segmentedFunctionCall(() -> validator.validate(value));
            if (violations.isEmpty()) {
                return value;
            }
            violations.forEach(
                    v -> LOG.warn("Json validation failed due to missing required field: {}", v));
            throw new JsonException(
                    "JSON validation error, missing required field(s): "
                            + String.join(", ", violations));
        } catch (JsonSyntaxException | IllegalArgumentException e) {
            throw new JsonException(e);
        }
    }

    @Override
    public String writeValueAsString(Object object) {
        return segmentedFunctionCall(() -> gson.toJson(object));
    }

    public static SerializationService getInstance() {
        if (isNull(INSTANCE)) {
            INSTANCE = new SerializationService();
        }
        return INSTANCE;
    }
}
