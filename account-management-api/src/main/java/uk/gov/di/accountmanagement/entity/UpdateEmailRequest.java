package uk.gov.di.accountmanagement.entity;

import com.fasterxml.jackson.annotation.JsonProperty;

public class UpdateEmailRequest {

    private final String existingEmailAddress;
    private final String replacementEmailAddress;
    private final String otp;

    public UpdateEmailRequest(
            @JsonProperty(required = true, value = "existingEmailAddress")
                    String existingEmailAddress,
            @JsonProperty(required = true, value = "replacementEmailAddress")
                    String replacementEmailAddress,
            @JsonProperty(required = true, value = "otp") String otp) {
        this.existingEmailAddress = existingEmailAddress.toLowerCase();
        this.replacementEmailAddress = replacementEmailAddress.toLowerCase();
        this.otp = otp;
    }

    public String getExistingEmailAddress() {
        return existingEmailAddress;
    }

    public String getReplacementEmailAddress() {
        return replacementEmailAddress;
    }

    public String getOtp() {
        return otp;
    }
}
