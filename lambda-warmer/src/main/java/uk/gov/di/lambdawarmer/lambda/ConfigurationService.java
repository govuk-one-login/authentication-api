package uk.gov.di.lambdawarmer.lambda;

import java.net.URI;
import java.util.Optional;

public class ConfigurationService {

    // Please keep the method names in alphabetical order so we can find stuff more easily.

    public String getAccessTokenExpiry() {
        return System.getenv().getOrDefault("ACCESS_TOKEN_EXPIRY", "300");
    }


}
