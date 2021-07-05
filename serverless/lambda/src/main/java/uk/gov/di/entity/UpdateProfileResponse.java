package uk.gov.di.entity;

import com.fasterxml.jackson.annotation.JsonProperty;

public class UpdateProfileResponse extends BaseAPIResponse {
    public UpdateProfileResponse(@JsonProperty("sessionState") SessionState sessionState) {
        super(sessionState);
    }
}
