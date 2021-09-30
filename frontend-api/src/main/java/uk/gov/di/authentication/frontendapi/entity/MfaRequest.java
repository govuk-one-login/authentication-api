package uk.gov.di.authentication.frontendapi.entity;

import com.fasterxml.jackson.annotation.JsonProperty;

public class MfaRequest extends BaseFrontendRequest {

    public MfaRequest(@JsonProperty(required = true, value = "email") String email) {
        super(email);
    }
}
