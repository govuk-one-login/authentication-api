package uk.gov.di.orchestration.entity;

import com.google.gson.annotations.Expose;
import uk.gov.di.orchestration.shared.validation.Required;

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
