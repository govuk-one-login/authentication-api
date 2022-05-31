package uk.gov.di.authentication.oidc.entity;

import com.google.gson.annotations.Expose;
import uk.gov.di.authentication.shared.validation.Required;

public class AuthCodeResponse {

    @Expose @Required private String location;

    public AuthCodeResponse() {}

    public AuthCodeResponse(String location) {
        this.location = location;
    }

    public String getLocation() {
        return location;
    }
}
