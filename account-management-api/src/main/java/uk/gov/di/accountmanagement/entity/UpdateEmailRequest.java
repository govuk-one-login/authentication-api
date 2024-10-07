package uk.gov.di.accountmanagement.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import uk.gov.di.authentication.shared.validation.Required;

public record UpdateEmailRequest(
        @Expose @SerializedName("existingEmailAddress") @Required String existingEmailAddress,
        @Expose @SerializedName("replacementEmailAddress") @Required String replacementEmailAddress,
        @Expose @Required String otp) {

    public UpdateEmailRequest(
            String existingEmailAddress, String replacementEmailAddress, String otp) {
        this.existingEmailAddress =
                existingEmailAddress != null ? existingEmailAddress.toLowerCase() : null;
        this.replacementEmailAddress =
                replacementEmailAddress != null ? replacementEmailAddress.toLowerCase() : null;
        this.otp = otp;
    }
}
