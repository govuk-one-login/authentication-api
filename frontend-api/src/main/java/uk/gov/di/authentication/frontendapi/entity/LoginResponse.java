package uk.gov.di.authentication.frontendapi.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import uk.gov.di.authentication.shared.validation.Required;

public class LoginResponse {

    @SerializedName("redactedPhoneNumber")
    @Expose
    private String redactedPhoneNumber;

    @SerializedName("mfaRequired")
    @Expose
    @Required
    private boolean mfaRequired;

    @SerializedName("phoneNumberVerified")
    @Expose
    @Required
    private boolean phoneNumberVerified;

    @SerializedName(value = "latestTermsAndConditionsAccepted")
    @Expose
    @Required
    private boolean latestTermsAndConditionsAccepted;

    @SerializedName(value = "consentRequired")
    @Expose
    @Required
    private boolean consentRequired;

    public LoginResponse() {}

    public LoginResponse(
            String redactedPhoneNumber,
            boolean mfaRequired,
            boolean phoneNumberVerified,
            boolean latestTermsAndConditionsAccepted,
            boolean consentRequired) {
        this.redactedPhoneNumber = redactedPhoneNumber;
        this.mfaRequired = mfaRequired;
        this.phoneNumberVerified = phoneNumberVerified;
        this.latestTermsAndConditionsAccepted = latestTermsAndConditionsAccepted;
        this.consentRequired = consentRequired;
    }

    public String getRedactedPhoneNumber() {
        return redactedPhoneNumber;
    }

    public boolean isMfaRequired() {
        return mfaRequired;
    }

    public boolean isPhoneNumberVerified() {
        return phoneNumberVerified;
    }

    public boolean getLatestTermsAndConditionsAccepted() {
        return latestTermsAndConditionsAccepted;
    }

    public boolean isConsentRequired() {
        return consentRequired;
    }
}
