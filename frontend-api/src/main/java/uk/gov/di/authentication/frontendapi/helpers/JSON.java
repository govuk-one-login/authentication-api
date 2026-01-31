package uk.gov.di.authentication.frontendapi.helpers;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

/**
 * This class is a manual shim to replace the auto-generated JSON utility class normally created by
 * the OpenAPI Generator.
 *
 * <p>We have disabled the 'supportingFiles' generation in build.gradle to prevent the generator
 * from creating a JSON.java that imports forbidden libraries (e.g., okio, gson-fire).
 *
 * <p>This shim provides the minimal functionality required by the generated POJOs (specifically the
 * {@code .toJson()} method) using only the allowed Gson library.
 */
public class JSON {
    private JSON() {
        /* This utility class should not be instantiated */
    }

    private static Gson gson;

    public static Gson getGson() {
        if (gson == null) {
            gson = new GsonBuilder().disableHtmlEscaping().create();
        }
        return gson;
    }
}
