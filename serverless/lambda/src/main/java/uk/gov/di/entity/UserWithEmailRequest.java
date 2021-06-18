package uk.gov.di.entity;

import com.fasterxml.jackson.annotation.JsonProperty;

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
