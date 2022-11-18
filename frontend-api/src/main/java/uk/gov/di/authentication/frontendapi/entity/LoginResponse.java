package uk.gov.di.authentication.frontendapi.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import uk.gov.di.authentication.shared.entity.MFAMethodType;
import uk.gov.di.authentication.shared.validation.Required;

public class LoginResponse {

    @SerializedName("redactedPhoneNumber")
    @Expose
    private String redactedPhoneNumber;

    @SerializedName("mfaRequired")
    @Expose
    @Required
    private boolean mfaRequired;

    @SerializedName("mfaMethodType")
    @Expose
    @Required
    private MFAMethodType mfaMethodType;

    @SerializedName("mfaMethodVerified")
    @Expose
    @Required
    private boolean mfaMethodVerified;

    @SerializedName(value = "latestTermsAndConditionsAccepted")
    @Expose
    @Required
    private boolean latestTermsAndConditionsAccepted;

    @SerializedName(value = "consentRequired")
    @Expose
    @Required
    private boolean consentRequired;

    @SerializedName(value = "passwordChangeRequired")
    @Expose
    @Required
    private boolean passwordChangeRequired;

    public LoginResponse() {}

    public LoginResponse(
            String redactedPhoneNumber,
            boolean mfaRequired,
            boolean latestTermsAndConditionsAccepted,
            boolean consentRequired,
            MFAMethodType mfaMethodType,
            boolean mfaMethodVerified,
            boolean passwordChangeRequired) {
        this.redactedPhoneNumber = redactedPhoneNumber;
        this.mfaRequired = mfaRequired;
        this.latestTermsAndConditionsAccepted = latestTermsAndConditionsAccepted;
        this.consentRequired = consentRequired;
        this.mfaMethodType = mfaMethodType;
        this.mfaMethodVerified = mfaMethodVerified;
        this.passwordChangeRequired = passwordChangeRequired;
    }

    public String getRedactedPhoneNumber() {
        return redactedPhoneNumber;
    }

    public boolean isMfaRequired() {
        return mfaRequired;
    }

    public boolean getLatestTermsAndConditionsAccepted() {
        return latestTermsAndConditionsAccepted;
    }

    public boolean isConsentRequired() {
        return consentRequired;
    }

    public MFAMethodType getMfaMethodType() {
        return mfaMethodType;
    }

    public boolean isMfaMethodVerified() {
        return mfaMethodVerified;
    }

    public boolean isPasswordChangeRequired() {
        return passwordChangeRequired;
    }
}
