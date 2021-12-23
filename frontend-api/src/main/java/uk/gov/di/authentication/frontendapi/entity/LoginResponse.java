package uk.gov.di.authentication.frontendapi.entity;

import com.fasterxml.jackson.annotation.JsonProperty;

public class LoginResponse {

    @JsonProperty("redactedPhoneNumber")
    private String redactedPhoneNumber;

    @JsonProperty("isMfaRequired")
    private boolean isMfaRequired;

    @JsonProperty("isPhoneNumberVerified")
    private boolean isPhoneNumberVerified;

    public LoginResponse(
            @JsonProperty(value = "redactedPhoneNumber") String redactedPhoneNumber,
            @JsonProperty(value = "isMfaRequired", required = true) boolean isMfaRequired,
            @JsonProperty(value = "isPhoneNumberVerified", required = true)
                    boolean isPhoneNumberVerified) {
        this.redactedPhoneNumber = redactedPhoneNumber;
        this.isMfaRequired = isMfaRequired;
        this.isPhoneNumberVerified = isPhoneNumberVerified;
    }

    public String getRedactedPhoneNumber() {
        return redactedPhoneNumber;
    }

    public boolean getIsMfaRequired() {
        return isMfaRequired;
    }

    public boolean getIsPhoneNumberVerified() {
        return isPhoneNumberVerified;
    }
}
