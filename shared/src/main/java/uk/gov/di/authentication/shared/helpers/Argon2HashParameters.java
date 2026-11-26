package uk.gov.di.authentication.shared.helpers;

import uk.gov.di.authentication.shared.services.ConfigurationService;

public record Argon2HashParameters(
        String algorithm, int algorithmVersion, int memory, int iterations, int parallelism) {

    public static final String ARGON2_ALGORITHM = "argon2id";
    public static final int ARGON2_ALGORITHM_VERSION = 19;

    public static Argon2HashParameters fromConfiguration(
            ConfigurationService configurationService) {
        return new Argon2HashParameters(
                ARGON2_ALGORITHM,
                ARGON2_ALGORITHM_VERSION,
                configurationService.getArgon2MemoryInKibibytes(),
                configurationService.getArgon2Iterations(),
                configurationService.getArgon2Parallelism());
    }
}
