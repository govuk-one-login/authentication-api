package uk.gov.di.accountmanagement.entity;

import com.google.gson.annotations.Expose;
import uk.gov.di.authentication.shared.validation.Required;

public class RemoveAccountRequest {
    @Expose @Required private String email;

    public RemoveAccountRequest() {}

    public RemoveAccountRequest(String email) {
        this.email = email;
    }

    public String getEmail() {
        return email;
    }
}
