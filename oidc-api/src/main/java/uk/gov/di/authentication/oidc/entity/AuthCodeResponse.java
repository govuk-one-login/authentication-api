package uk.gov.di.authentication.oidc.entity;

import com.fasterxml.jackson.annotation.JsonProperty;

public class AuthCodeResponse {

    @JsonProperty("location")
    private String location;

    public AuthCodeResponse(@JsonProperty(required = true, value = "location") String location) {
        this.location = location;
    }

    public String getLocation() {
        return location;
    }
}
