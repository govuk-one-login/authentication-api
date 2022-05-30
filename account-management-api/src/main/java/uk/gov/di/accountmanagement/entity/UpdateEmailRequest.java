package uk.gov.di.accountmanagement.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import jakarta.validation.constraints.NotNull;

public class UpdateEmailRequest {

    @Expose
    @SerializedName("existingEmailAddress")
    @NotNull
    private String existingEmailAddress;

    @Expose
    @SerializedName("replacementEmailAddress")
    @NotNull
    private String replacementEmailAddress;

    @Expose @NotNull private String otp;

    public UpdateEmailRequest() {}

    public UpdateEmailRequest(
            String existingEmailAddress, String replacementEmailAddress, String otp) {
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
