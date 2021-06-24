package uk.gov.di.entity;

import com.fasterxml.jackson.annotation.JsonProperty;

public class VerifyCodeResponse extends BaseAPIResponse {
    public VerifyCodeResponse(@JsonProperty("sessionState") SessionState sessionState) {
        super(sessionState);
    }
}
