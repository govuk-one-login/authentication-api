package uk.gov.di.authentication.frontendapi.entity;

import com.fasterxml.jackson.annotation.JsonProperty;
import uk.gov.di.authentication.shared.entity.BaseAPIResponse;
import uk.gov.di.authentication.shared.entity.SessionState;

public class LoginResponse extends BaseAPIResponse {

    @JsonProperty("redactedPhoneNumber")
    private String redactedPhoneNumber;

    public LoginResponse(
            @JsonProperty(value = "redactedPhoneNumber") String redactedPhoneNumber,
            @JsonProperty(required = true, value = "sessionState") SessionState sessionState) {
        super(sessionState);
        this.redactedPhoneNumber = redactedPhoneNumber;
    }

    public String getRedactedPhoneNumber() {
        return redactedPhoneNumber;
    }
}
