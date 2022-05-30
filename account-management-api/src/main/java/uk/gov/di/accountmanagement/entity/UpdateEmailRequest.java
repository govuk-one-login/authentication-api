package uk.gov.di.accountmanagement.entity;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

public class UpdateEmailRequest {

    @Expose
    @SerializedName("existingEmailAddress")
    private String existingEmailAddress;

    @Expose
    @SerializedName("replacementEmailAddress")
    private String replacementEmailAddress;

    @Expose private String otp;

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
