package uk.gov.di.entity;

import com.fasterxml.jackson.annotation.JsonProperty;

public class LoginResponse extends BaseAPIResponse {
    public LoginResponse(@JsonProperty("sessionState") SessionState sessionState) {
        super(sessionState);
    }
}
