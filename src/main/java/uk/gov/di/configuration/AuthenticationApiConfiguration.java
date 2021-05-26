package uk.gov.di.configuration;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.dropwizard.Configuration;

import javax.validation.constraints.NotNull;
import java.net.URI;

public class AuthenticationApiConfiguration extends Configuration {

    @JsonProperty @NotNull private String issuer;
    @JsonProperty
    @NotNull
    private String clientId;
    @JsonProperty @NotNull private String clientSecret;
    @JsonProperty @NotNull private URI baseUrl;


    public String getIssuer() {
        return issuer;
    }

    public URI getBaseUrl() {
        return baseUrl;
    }

    public String getClientId() {
        return clientId;
    }

    public String getClientSecret() {
        return clientSecret;
    }


}
