package uk.gov.di.authentication.frontendapi.entity;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotNull;
import uk.gov.di.authentication.shared.entity.BaseFrontendRequest;

public class LoginRequest extends BaseFrontendRequest {

    @JsonProperty(required = true, value = "password")
    @NotNull
    private String password;

    public LoginRequest() {}

    public LoginRequest(String email, String password) {
        this.email = email;
        this.password = password;
    }

    public String getPassword() {
        return password;
    }
}
