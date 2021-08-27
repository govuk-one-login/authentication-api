package uk.gov.di.accountmanagement.entity;

import com.fasterxml.jackson.annotation.JsonProperty;

public class AuthenticateResponse extends BaseAPIResponse {

    @JsonProperty("redactedPhoneNumber")
    private String redactedPhoneNumber;

    public AuthenticateResponse(
            @JsonProperty(required = true, value = "redactedPhoneNumber")
                    String redactedPhoneNumber,
            @JsonProperty(required = true, value = "sessionState") SessionState sessionState) {
        super(sessionState);
        this.redactedPhoneNumber = redactedPhoneNumber;
    }

    public String getRedactedPhoneNumber() {
        return redactedPhoneNumber;
    }
}
