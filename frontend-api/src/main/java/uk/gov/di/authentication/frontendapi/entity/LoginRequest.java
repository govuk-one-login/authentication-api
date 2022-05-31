package uk.gov.di.authentication.frontendapi.entity;

import com.google.gson.annotations.Expose;
import uk.gov.di.authentication.shared.entity.BaseFrontendRequest;
import uk.gov.di.authentication.shared.validation.Required;

public class LoginRequest extends BaseFrontendRequest {

    @Expose @Required private String password;

    public LoginRequest() {}

    public LoginRequest(String email, String password) {
        this.email = email;
        this.password = password;
    }

    public String getPassword() {
        return password;
    }
}
