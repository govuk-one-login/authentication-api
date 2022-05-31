package uk.gov.di.accountmanagement.entity;

import com.google.gson.annotations.Expose;
import uk.gov.di.authentication.shared.validation.Required;

public class AuthenticateRequest {

    @Expose @Required private String email;

    @Expose @Required private String password;

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
