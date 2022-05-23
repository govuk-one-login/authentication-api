package uk.gov.di.accountmanagement.entity;

import com.google.gson.annotations.Expose;
import jakarta.validation.constraints.NotNull;

public class AuthenticateRequest {

    @Expose @NotNull private String email;

    @Expose @NotNull private String password;

    public AuthenticateRequest() {}

    public AuthenticateRequest(String email, String password) {
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
