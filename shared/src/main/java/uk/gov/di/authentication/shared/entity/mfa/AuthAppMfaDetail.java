package uk.gov.di.authentication.shared.entity.mfa;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import uk.gov.di.authentication.shared.validation.Required;

public record AuthAppMfaDetail(
        @Expose @Required @SerializedName("mfaMethodType") MFAMethodType mfaMethodType,
        @Expose @Required @SerializedName("credential") String credential)
        implements MfaDetail {

    public AuthAppMfaDetail(String credential) {
        this(MFAMethodType.AUTH_APP, credential);
    }
}
