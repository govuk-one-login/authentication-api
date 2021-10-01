package uk.gov.di.authentication.frontendapi.entity;

import com.fasterxml.jackson.annotation.JsonProperty;

public class CheckUserExistsRequest extends BaseFrontendRequest {
    public CheckUserExistsRequest(@JsonProperty(required = true, value = "email") String email) {
        super(email);
    }

    @Override
    public String toString() {
        return "CheckUserExistsRequest{" + "email='" + email + '\'' + '}';
    }
}
