package uk.gov.di.authentication.frontendapi.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import uk.gov.di.authentication.entity.UserMfaDetail;
import uk.gov.di.authentication.shared.entity.mfaMethodManagement.MFAMethodType;
import uk.gov.di.authentication.shared.validation.Required;

public record LoginResponse(
        @SerializedName("redactedPhoneNumber") @Expose String redactedPhoneNumber,
        @SerializedName("mfaRequired") @Expose @Required boolean mfaRequired,
        @SerializedName(value = "latestTermsAndConditionsAccepted") @Expose @Required
                boolean latestTermsAndConditionsAccepted,
        @SerializedName("mfaMethodType") @Expose @Required MFAMethodType mfaMethodType,
        @SerializedName("mfaMethodVerified") @Expose @Required boolean mfaMethodVerified,
        @SerializedName(value = "passwordChangeRequired") @Expose @Required
                boolean passwordChangeRequired) {

    public LoginResponse(
            String redactedPhoneNumber,
            UserMfaDetail mfaDetail,
            boolean latestTermsAndConditionsAccepted,
            boolean passwordChangeRequired) {
        this(
                redactedPhoneNumber,
                mfaDetail.isMfaRequired(),
                latestTermsAndConditionsAccepted,
                mfaDetail.mfaMethodType(),
                mfaDetail.mfaMethodVerified(),
                passwordChangeRequired);
    }
}
