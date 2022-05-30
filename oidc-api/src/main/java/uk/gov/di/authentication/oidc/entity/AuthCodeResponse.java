package uk.gov.di.authentication.oidc.entity;

import com.google.gson.annotations.Expose;
import jakarta.validation.constraints.NotNull;

public class AuthCodeResponse {

    @Expose @NotNull private String location;

    public AuthCodeResponse() {}

    public AuthCodeResponse(String location) {
        this.location = location;
    }

    public String getLocation() {
        return location;
    }
}
