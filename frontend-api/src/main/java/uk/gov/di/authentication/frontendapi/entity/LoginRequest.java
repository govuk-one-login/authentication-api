package uk.gov.di.authentication.frontendapi.entity;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotNull;

public class LoginRequest extends BaseFrontendRequest {

    @JsonProperty(required = true, value = "password")
    @NotNull
    private String password;

    public LoginRequest() {}
    ;

    private LoginRequest(String email, String password) {
        this.email = email;
        this.password = password;
    }

    public String getPassword() {
        return password;
    }

    public static LoginRequest create(String email, String password) {
        return new LoginRequest(email, password);
    }
}
