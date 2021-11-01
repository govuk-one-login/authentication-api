package uk.gov.di.authentication.frontendapi.entity;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotNull;

public class SignupRequest extends BaseFrontendRequest {

    @JsonProperty(required = true, value = "password")
    @NotNull
    private String password;

    public String getPassword() {
        return password;
    }
}
