package uk.gov.di.authentication.shared.services;

import com.google.gson.FieldNamingPolicy;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonSyntaxException;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.shared.annotations.Instrumented;
import uk.gov.di.authentication.shared.helpers.InstrumentationHelper;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.serialization.LocalDateTimeAdapter;
import uk.gov.di.authentication.shared.serialization.StateAdapter;
import uk.gov.di.authentication.shared.serialization.SubjectAdapter;
import uk.gov.di.authentication.shared.validation.RequiredFieldValidator;
import uk.gov.di.authentication.shared.validation.Validator;

import java.time.LocalDateTime;

import static java.util.Objects.isNull;

public class SerializationService implements Json {

    private static SerializationService INSTANCE;
    private static Logger LOG = LogManager.getLogger(SerializationService.class);

    private final Gson gsonWithUnderscores;
    private final Gson gsonWithCamelCase;
    private final Gson gsonWithUnderscoresNoNulls;

    private final RequiredFieldValidator defaultValidator = new RequiredFieldValidator();

    public SerializationService() {
        gsonWithUnderscores =
                createGsonBuilder(FieldNamingPolicy.LOWER_CASE_WITH_UNDERSCORES).create();
        gsonWithCamelCase = createGsonBuilder(FieldNamingPolicy.IDENTITY).create();
        gsonWithUnderscoresNoNulls =
                createNoNullGsonBuilder(FieldNamingPolicy.LOWER_CASE_WITH_UNDERSCORES).create();
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
        InstrumentationHelper.addAnnotation("serialization_method", "writeValueAsString");
        return gsonWithUnderscores.toJson(object);
    }

    @Override
    @Instrumented("SerializationService::GSON::toJson")
    public String writeValueAsStringCamelCase(Object object) {
        InstrumentationHelper.addAnnotation("serialization_method", "writeValueAsStringCamelCase");
        return gsonWithCamelCase.toJson(object);
    }

    @Instrumented("SerializationService::GSON::toJson")
    public String writeValueAsStringNoNulls(Object object) {
        InstrumentationHelper.addAnnotation("serialization_method", "writeValueAsStringNoNulls");
        return gsonWithUnderscoresNoNulls.toJson(object);
    }

    public static SerializationService getInstance() {
        if (isNull(INSTANCE)) {
            INSTANCE = new SerializationService();
        }
        return INSTANCE;
    }

    private GsonBuilder createGsonBuilder(FieldNamingPolicy namingPolicy) {
        return createNoNullGsonBuilder(namingPolicy).serializeNulls();
    }

    private GsonBuilder createNoNullGsonBuilder(FieldNamingPolicy namingPolicy) {
        return new GsonBuilder()
                .setFieldNamingPolicy(namingPolicy)
                .excludeFieldsWithoutExposeAnnotation()
                .registerTypeAdapter(State.class, new StateAdapter())
                .registerTypeAdapter(LocalDateTime.class, new LocalDateTimeAdapter())
                .registerTypeAdapter(Subject.class, new SubjectAdapter());
    }
}
