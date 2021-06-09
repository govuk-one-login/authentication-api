package uk.gov.di.services;

import java.net.URI;
import java.util.Optional;

public class ConfigurationService {

    public Optional<String> getBaseURL() {
        return Optional.ofNullable(System.getenv("BASE_URL"));
    }

    public URI getLoginURI() {
        return URI.create(System.getenv("LOGIN_URI"));
    }
}
