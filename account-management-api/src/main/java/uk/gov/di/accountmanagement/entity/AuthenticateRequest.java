package uk.gov.di.accountmanagement.entity;

import com.fasterxml.jackson.annotation.JsonProperty;

public class AuthenticateRequest {

    private String email;
    private String password;

    public AuthenticateRequest(
            @JsonProperty(required = true, value = "email") String email,
            @JsonProperty(required = true, value = "password") String password) {
        this.email = email;
        this.password = password;
    }

    public String getEmail() {
        return email;
    }

    public String getPassword() {
        return password;
    }
}
