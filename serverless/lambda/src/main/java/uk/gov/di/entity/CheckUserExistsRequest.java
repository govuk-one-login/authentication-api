package uk.gov.di.entity;

import com.fasterxml.jackson.annotation.JsonProperty;

public class CheckUserExistsRequest {

    private String email;

    public CheckUserExistsRequest(@JsonProperty(required = true, value = "email") String email) {
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
