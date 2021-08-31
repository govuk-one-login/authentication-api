package uk.gov.di.authentication.frontendapi.entity;

import com.fasterxml.jackson.annotation.JsonProperty;

public class LoginRequest {

    private String email;
    private String password;

    public LoginRequest(
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
