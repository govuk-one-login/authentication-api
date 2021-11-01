package uk.gov.di.authentication.frontendapi.entity;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotNull;

@JsonIgnoreProperties(ignoreUnknown = true)
public class BaseFrontendRequest {
    @NotNull
    @JsonProperty("email")
    protected String email;

    public String getEmail() {
        return email;
    }
}
