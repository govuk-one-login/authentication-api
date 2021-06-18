package uk.gov.di.entity;

import com.fasterxml.jackson.annotation.JsonProperty;

public class SignupResponse extends BaseAPIResponse {
    public SignupResponse(@JsonProperty("sessionState") SessionState sessionState) {
        super(sessionState);
    }
}
