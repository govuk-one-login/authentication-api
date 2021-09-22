package uk.gov.di.authentication.frontendapi.entity;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonIgnoreProperties(ignoreUnknown = true)
public class BaseFrontendRequest {
    protected String email;

    public BaseFrontendRequest(@JsonProperty(required = true, value = "email") String email) {
        this.email = email;
    }

    public String getEmail() {
        return email;
    }
}
