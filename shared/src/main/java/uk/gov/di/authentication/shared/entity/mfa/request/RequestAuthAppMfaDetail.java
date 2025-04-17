package uk.gov.di.authentication.shared.entity.mfa.request;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.entity.mfa.MfaDetail;
import uk.gov.di.authentication.shared.validation.Required;

public record RequestAuthAppMfaDetail(
        @Expose @Required @SerializedName("mfaMethodType") MFAMethodType mfaMethodType,
        @Expose @Required @SerializedName("credential") String credential)
        implements MfaDetail {

    public RequestAuthAppMfaDetail(String credential) {
        this(MFAMethodType.AUTH_APP, credential);
    }
}
