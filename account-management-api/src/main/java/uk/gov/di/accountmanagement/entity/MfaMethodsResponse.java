package uk.gov.di.accountmanagement.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import uk.gov.di.authentication.shared.entity.MFAMethod;
import uk.gov.di.authentication.shared.validation.Required;

import java.util.List;

public class MfaMethodsResponse {

    @SerializedName("mfaMethods")
    @Expose
    @Required
    private List<MFAMethod> mfaMethods;

    public MfaMethodsResponse(List<MFAMethod> mfaMethods) {
        this.mfaMethods = mfaMethods;
    }

    public List<MFAMethod> getMfaMethods() {
        return mfaMethods;
    }
}
