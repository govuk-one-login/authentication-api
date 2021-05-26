package uk.gov.di.configuration;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.dropwizard.Configuration;

import javax.validation.constraints.NotNull;
import java.net.URI;

public class AuthenticationApiConfiguration extends Configuration {

    @JsonProperty
    @NotNull
    private URI baseUrl;

    public URI getBaseUrl() {
        return baseUrl;
    }

}
