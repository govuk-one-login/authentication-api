package uk.gov.di.authentication.frontendapi.entity;

import com.google.gson.annotations.Expose;
import jakarta.validation.constraints.NotNull;
import uk.gov.di.authentication.shared.entity.BaseFrontendRequest;

public class LoginRequest extends BaseFrontendRequest {

    @Expose @NotNull private String password;

    public LoginRequest() {}

    public LoginRequest(String email, String password) {
        this.email = email;
        this.password = password;
    }

    public String getPassword() {
        return password;
    }
}
