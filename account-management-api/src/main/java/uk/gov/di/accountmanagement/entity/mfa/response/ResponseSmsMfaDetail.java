package uk.gov.di.accountmanagement.entity.mfa.response;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.entity.mfa.MfaDetail;
import uk.gov.di.authentication.shared.validation.Required;

public record ResponseSmsMfaDetail(
        @Expose @Required @SerializedName("mfaMethodType") MFAMethodType mfaMethodType,
        @Expose @Required @SerializedName("phoneNumber") String phoneNumber)
        implements MfaDetail {

    public ResponseSmsMfaDetail(String phoneNumber) {
        this(MFAMethodType.SMS, phoneNumber);
    }
}
