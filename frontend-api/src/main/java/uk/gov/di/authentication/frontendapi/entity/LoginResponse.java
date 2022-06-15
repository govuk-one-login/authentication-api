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
            boolean consentRequired,
            MFAMethodType mfaMethodType,
            boolean mfaMethodVerified) {
        this.redactedPhoneNumber = redactedPhoneNumber;
        this.mfaRequired = mfaRequired;
        this.phoneNumberVerified = phoneNumberVerified;
        this.latestTermsAndConditionsAccepted = latestTermsAndConditionsAccepted;
        this.consentRequired = consentRequired;
        this.mfaMethodType = mfaMethodType;
        this.mfaMethodVerified = mfaMethodVerified;
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

    public MFAMethodType getMfaMethodType() {
        return mfaMethodType;
    }

    public boolean isMfaMethodVerified() {
        return mfaMethodVerified;
    }
}
