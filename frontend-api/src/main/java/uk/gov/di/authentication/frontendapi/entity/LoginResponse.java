package uk.gov.di.authentication.frontendapi.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import uk.gov.di.authentication.entity.UserMfaDetail;
import uk.gov.di.authentication.frontendapi.entity.mfa.MfaMethodResponse;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.validation.Required;

import java.util.List;

public record LoginResponse(
        @SerializedName("redactedPhoneNumber") @Expose String redactedPhoneNumber,
        @SerializedName("mfaRequired") @Expose @Required boolean mfaRequired,
        @SerializedName(value = "latestTermsAndConditionsAccepted") @Expose @Required
                boolean latestTermsAndConditionsAccepted,
        @SerializedName("mfaMethodType") @Expose @Required MFAMethodType mfaMethodType,
        @SerializedName("mfaMethodVerified") @Expose @Required boolean mfaMethodVerified,
        @SerializedName("mfaMethods") @Expose @Required List<MfaMethodResponse> mfaMethodResponses,
        @SerializedName(value = "passwordChangeRequired") @Expose @Required
                boolean passwordChangeRequired) {

    public LoginResponse(
            String redactedPhoneNumber,
            UserMfaDetail mfaDetail,
            boolean latestTermsAndConditionsAccepted,
            List<MfaMethodResponse> mfaMethodResponses,
            boolean passwordChangeRequired) {
        this(
                redactedPhoneNumber,
                mfaDetail.isMfaRequired(),
                latestTermsAndConditionsAccepted,
                mfaDetail.mfaMethodType(),
                mfaDetail.mfaMethodVerified(),
                mfaMethodResponses,
                passwordChangeRequired);
    }
}
