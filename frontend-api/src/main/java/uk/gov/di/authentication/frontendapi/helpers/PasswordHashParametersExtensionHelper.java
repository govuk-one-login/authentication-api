package uk.gov.di.authentication.frontendapi.helpers;

import uk.gov.di.authentication.shared.helpers.Argon2HashParameters;

import java.util.LinkedHashMap;
import java.util.Map;

public class PasswordHashParametersExtensionHelper {

    public static final String CURRENT_KEY = "password_hash_parameters_current";
    public static final String REHASHED_KEY = "password_hash_parameters_rehashed";
    public static final String UPDATED_KEY = "password_hash_parameters_updated";
    public static final String ALGORITHM_KEY = "password_hash_parameters_algorithm";
    public static final String ALGORITHM_VERSION_KEY = "password_hash_parameters_algorithm_version";
    public static final String MEMORY_KEY = "password_hash_parameters_memory";
    public static final String ITERATIONS_KEY = "password_hash_parameters_iterations";
    public static final String PARALLELISM_KEY = "password_hash_parameters_parallelism";

    private PasswordHashParametersExtensionHelper() {}

    public static Map<String, Object> create(
            Argon2HashParameters currentParameters,
            boolean rehashed,
            Argon2HashParameters updatedParameters) {
        var extension = new LinkedHashMap<String, Object>();
        extension.put(CURRENT_KEY, toHashParametersMap(currentParameters));
        extension.put(REHASHED_KEY, rehashed);
        if (updatedParameters != null) {
            extension.put(UPDATED_KEY, toHashParametersMap(updatedParameters));
        }
        return extension;
    }

    private static Map<String, Object> toHashParametersMap(Argon2HashParameters parameters) {
        var map = new LinkedHashMap<String, Object>();
        map.put(ALGORITHM_KEY, parameters.algorithm());
        map.put(ALGORITHM_VERSION_KEY, String.valueOf(parameters.algorithmVersion()));
        map.put(MEMORY_KEY, parameters.memory());
        map.put(ITERATIONS_KEY, parameters.iterations());
        map.put(PARALLELISM_KEY, parameters.parallelism());
        return map;
    }
}
