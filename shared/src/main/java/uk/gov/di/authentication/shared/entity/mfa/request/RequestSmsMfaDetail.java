package uk.gov.di.authentication.shared.entity.mfa.request;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.entity.mfa.MfaDetail;
import uk.gov.di.authentication.shared.validation.Required;

public record RequestSmsMfaDetail(
        @Expose @Required @SerializedName("mfaMethodType") MFAMethodType mfaMethodType,
        @Expose @Required @SerializedName("phoneNumber") String phoneNumber,
        @Expose @Required @SerializedName("otp") String otp)
        implements MfaDetail {

    public RequestSmsMfaDetail(String phoneNumber, String otp) {
        this(MFAMethodType.SMS, phoneNumber, otp);
    }
}
