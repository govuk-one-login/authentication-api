package uk.gov.di.authentication.shared.services;

import com.google.gson.FieldNamingPolicy;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.shared.serialization.Json;

import static java.util.Objects.isNull;

public class SerializationService implements Json {

    private static SerializationService INSTANCE;
    private static Logger LOG = LogManager.getLogger(SerializationService.class);

    private final Gson gson;

    public SerializationService() {
        gson =
                new GsonBuilder()
                        .setFieldNamingPolicy(FieldNamingPolicy.LOWER_CASE_WITH_UNDERSCORES)
                        .serializeNulls()
                        .excludeFieldsWithoutExposeAnnotation()
                        .create();
    }

    @Override
    public <T> T readValue(String jsonString, Class<T> clazz) {
        return gson.fromJson(jsonString, clazz);
    }

    @Override
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
