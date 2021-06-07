package uk.gov.di.entity;

import com.fasterxml.jackson.annotation.JsonProperty;


public class SignupRequest {

    private String email;
    private String password;

    public SignupRequest(
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
