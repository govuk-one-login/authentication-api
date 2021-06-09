package uk.gov.di.services;

import java.util.Optional;

public class ConfigurationService {

    public Optional<String> getBaseURL() {
        return Optional.ofNullable(System.getenv("BASE_URL"));
    }

    public Optional<String> getLoginURL() {
        return Optional.ofNullable(System.getenv("LOGIN_URL"));
    }
}
