package uk.gov.di.authentication.shared.services;

import com.google.gson.FieldNamingPolicy;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonSyntaxException;
import com.google.gson.TypeAdapter;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.serialization.LocalDateTimeAdapter;
import uk.gov.di.authentication.shared.serialization.StateAdapter;
import uk.gov.di.authentication.shared.serialization.SubjectAdapter;
import uk.gov.di.authentication.shared.validation.RequiredFieldValidator;
import uk.gov.di.authentication.shared.validation.Validator;

import java.lang.reflect.Type;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

import static java.util.Objects.isNull;
import static uk.gov.di.authentication.shared.helpers.InstrumentationHelper.segmentedFunctionCall;

public class SerializationService implements Json {

    private static SerializationService INSTANCE;
    private static Logger LOG = LogManager.getLogger(SerializationService.class);

    private final Gson gsonWithUnderscores;
    private final Gson gsonWithCamelCase;
    private final Gson gsonWithUnderscoresNoNulls;

    private static final String SEGMENT_NAME = "SerializationService::GSON::toJson";
    private final RequiredFieldValidator defaultValidator = new RequiredFieldValidator();

    public SerializationService() {
        this(new HashMap<>());
    }

    public SerializationService(Map<Type, TypeAdapter<?>> extraTypeAdapters) {
        gsonWithUnderscores =
                createGsonBuilder(FieldNamingPolicy.LOWER_CASE_WITH_UNDERSCORES, extraTypeAdapters)
                        .create();
        gsonWithCamelCase =
                createGsonBuilder(FieldNamingPolicy.IDENTITY, extraTypeAdapters).create();
        gsonWithUnderscoresNoNulls =
                createNoNullGsonBuilder(
                                FieldNamingPolicy.LOWER_CASE_WITH_UNDERSCORES, extraTypeAdapters)
                        .create();
    }

    @Override
    public <T> T readValueUnchecked(String jsonString, Class<T> clazz) {
        try {
            return readValue(jsonString, clazz, defaultValidator, false);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public <T> T readValue(String jsonString, Class<T> clazz) throws JsonException {
        return readValue(jsonString, clazz, defaultValidator, false);
    }

    @Override
    public <T> T readValue(String body, Class<T> klass, Validator validator) throws JsonException {
        return readValue(body, klass, validator, false);
    }

    public <T> T readValue(String body, Class<T> klass, boolean useCamelCase) throws JsonException {
        return readValue(body, klass, defaultValidator, useCamelCase);
    }

    public <T> T readValue(
            String jsonString, Class<T> clazz, Validator validator, boolean useCamelCase)
            throws JsonException {
        Gson gson = useCamelCase ? gsonWithCamelCase : gsonWithUnderscores;
        return deserializeJson(jsonString, clazz, validator, gson);
    }

    private <T> T deserializeJson(String jsonString, Class<T> clazz, Validator validator, Gson gson)
            throws JsonException {
        try {
            T value =
                    segmentedFunctionCall(
                            "SerializationService::GSON::fromJson",
                            () -> gson.fromJson(jsonString, clazz));
            validateJson(value, validator);
            return value;
        } catch (JsonSyntaxException | IllegalArgumentException e) {
            LOG.error("Error during JSON deserialization", e);
            throw new JsonException(e);
        }
    }

    private <T> void validateJson(T value, Validator validator) throws JsonException {
        var violations =
                segmentedFunctionCall(
                        "SerializationService::validator::validate",
                        () -> validator.validate(value));
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
    public String writeValueAsString(Object object) {
        return segmentedFunctionCall(SEGMENT_NAME, () -> gsonWithUnderscores.toJson(object));
    }

    @Override
    public String writeValueAsStringCamelCase(Object object) {
        return segmentedFunctionCall(SEGMENT_NAME, () -> gsonWithCamelCase.toJson(object));
    }

    public String writeValueAsStringNoNulls(Object object) {
        return segmentedFunctionCall(SEGMENT_NAME, () -> gsonWithUnderscoresNoNulls.toJson(object));
    }

    public static SerializationService getInstance() {
        if (isNull(INSTANCE)) {
            INSTANCE = new SerializationService();
        }
        return INSTANCE;
    }

    private GsonBuilder createGsonBuilder(
            FieldNamingPolicy namingPolicy, Map<Type, TypeAdapter<?>> extraTypeAdapters) {
        return createNoNullGsonBuilder(namingPolicy, extraTypeAdapters).serializeNulls();
    }

    private GsonBuilder createNoNullGsonBuilder(
            FieldNamingPolicy namingPolicy, Map<Type, TypeAdapter<?>> extraTypeAdapters) {
        var builder =
                new GsonBuilder()
                        .setFieldNamingPolicy(namingPolicy)
                        .excludeFieldsWithoutExposeAnnotation()
                        .registerTypeAdapter(State.class, new StateAdapter())
                        .registerTypeAdapter(LocalDateTime.class, new LocalDateTimeAdapter())
                        .registerTypeAdapter(Subject.class, new SubjectAdapter());
        extraTypeAdapters.forEach(builder::registerTypeAdapter);
        return builder;
    }
}
