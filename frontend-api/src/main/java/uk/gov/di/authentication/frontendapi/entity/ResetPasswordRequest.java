package uk.gov.di.authentication.frontendapi.entity;

import com.fasterxml.jackson.annotation.JsonProperty;

public class ResetPasswordRequest extends BaseFrontendRequest {

    public ResetPasswordRequest(@JsonProperty(required = true, value = "email") String email) {
        super(email);
    }

    @Override
    public String toString() {
        return "ResetPasswordRequest{" + "email='" + email + '\'' + '}';
    }
}
