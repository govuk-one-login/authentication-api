package uk.gov.di.authentication.frontendapi.features;

import java.security.SecureRandom;

public class FeatureStrategies {

    private static final SecureRandom RANDOM = new SecureRandom();

    private FeatureStrategies() {}

    public static boolean fiftyFiftyStrategy() {
        return RANDOM.nextBoolean();
    }
}
