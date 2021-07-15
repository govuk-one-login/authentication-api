package uk.gov.di.entity;

import com.fasterxml.jackson.annotation.JsonProperty;

public class LoginResponse extends BaseAPIResponse {

    @JsonProperty("redactedPhoneNumber")
    private String redactedPhoneNumber;

    public LoginResponse(
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
