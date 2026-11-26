package uk.gov.di.authentication.frontendapi.helpers;

import com.google.gson.Gson;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.helpers.Argon2HashParameters;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

class PasswordHashParametersExtensionHelperTest {

    private static final Gson GSON = new Gson();

    private static final Argon2HashParameters CURRENT =
            new Argon2HashParameters("argon2id", 19, 15360, 2, 1);
    private static final Argon2HashParameters UPDATED =
            new Argon2HashParameters("argon2id", 19, 32768, 2, 1);

    private static final String REHASHED_EXAMPLE =
            """
            {
              "password_hash_parameters_current": {
                "password_hash_parameters_algorithm": "argon2id",
                "password_hash_parameters_algorithm_version": "19",
                "password_hash_parameters_memory": 15360,
                "password_hash_parameters_iterations": 2,
                "password_hash_parameters_parallelism": 1
              },
              "password_hash_parameters_rehashed": true,
              "password_hash_parameters_updated": {
                "password_hash_parameters_algorithm": "argon2id",
                "password_hash_parameters_algorithm_version": "19",
                "password_hash_parameters_memory": 32768,
                "password_hash_parameters_iterations": 2,
                "password_hash_parameters_parallelism": 1
              }
            }
            """;

    private static final String NOT_REHASHED_EXAMPLE =
            """
            {
              "password_hash_parameters_current": {
                "password_hash_parameters_algorithm": "argon2id",
                "password_hash_parameters_algorithm_version": "19",
                "password_hash_parameters_memory": 15360,
                "password_hash_parameters_iterations": 2,
                "password_hash_parameters_parallelism": 1
              },
              "password_hash_parameters_rehashed": false
            }
            """;

    @Test
    void shouldMatchCatalogueExampleWhenRehashed() {
        var extension = PasswordHashParametersExtensionHelper.create(CURRENT, true, UPDATED);

        assertEquals(JsonParser.parseString(REHASHED_EXAMPLE), GSON.toJsonTree(extension));
    }

    @Test
    void shouldMatchCatalogueExampleWhenNotRehashed() {
        var extension = PasswordHashParametersExtensionHelper.create(CURRENT, false, null);

        assertEquals(JsonParser.parseString(NOT_REHASHED_EXAMPLE), GSON.toJsonTree(extension));
    }

    @Test
    void shouldOmitUpdatedWhenNull() {
        var extension = PasswordHashParametersExtensionHelper.create(CURRENT, false, null);

        assertFalse(extension.containsKey("password_hash_parameters_updated"));
    }
}
