package uk.gov.di.accountmanagement.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import uk.gov.di.authentication.shared.validation.Required;

public class UpdateEmailRequest {

    @Expose
    @SerializedName("existingEmailAddress")
    @Required
    private String existingEmailAddress;

    @Expose
    @SerializedName("replacementEmailAddress")
    @Required
    private String replacementEmailAddress;

    @Expose @Required private String otp;

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
