package uk.gov.di.authentication.shared.services;

import com.google.gson.FieldNamingPolicy;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import static java.util.Objects.isNull;

public class SerializationService {

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

    public <T> T deserialize(String jsonString, Class<T> clazz) {
        return gson.fromJson(jsonString, clazz);
    }

    public <T> String serialize(T object, Class<T> clazz) {
        return gson.toJson(object, clazz);
    }

    public static SerializationService getInstance() {
        if (isNull(INSTANCE)) {
            INSTANCE = new SerializationService();
        }
        return INSTANCE;
    }
}
