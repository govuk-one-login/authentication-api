package uk.gov.di.authentication.shared.entity.mfa;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import uk.gov.di.authentication.shared.validation.Required;

public record SmsMfaDetail(
        @Expose @Required @SerializedName("mfaMethodType") MFAMethodType mfaMethodType,
        @Expose @Required @SerializedName("phoneNumber") String phoneNumber)
        implements MfaDetail {

    public SmsMfaDetail(String phoneNumber) {
        this(MFAMethodType.SMS, phoneNumber);
    }
}
