package uk.gov.di.accountmanagement.entity;

import com.google.gson.annotations.Expose;
import uk.gov.di.authentication.shared.validation.Required;

public class GetMfaMethodsRequest {

    @Expose @Required private String email;

    public GetMfaMethodsRequest(String email) {
        this.email = email;
    }

    public String getEmail() {
        return email;
    }
}
