package uk.gov.di.authentication.frontendapi.entity;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonIgnoreProperties(ignoreUnknown = true)
public class UserWithEmailRequest {
    protected String email;

    public UserWithEmailRequest(@JsonProperty(required = true, value = "email") String email) {
        this.email = email;
    }

    public String getEmail() {
        return email;
    }

    @Override
    public String toString() {
        return "CheckUserExistsRequest{" + "email='" + email + '\'' + '}';
    }
}
