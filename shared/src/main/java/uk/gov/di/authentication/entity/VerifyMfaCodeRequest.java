package uk.gov.di.authentication.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.MFAMethodType;
import uk.gov.di.authentication.shared.validation.Required;

public class VerifyMfaCodeRequest extends CodeRequest {

    public VerifyMfaCodeRequest() {}

    public VerifyMfaCodeRequest(
            MFAMethodType mfaMethodType,
            String code,
            boolean isRegistration,
            JourneyType journeyType) {
        this(mfaMethodType, code, isRegistration, journeyType, null);
    }

    public VerifyMfaCodeRequest(
            MFAMethodType mfaMethodType,
            String code,
            boolean isRegistration,
            JourneyType journeyType,
            String profileInformation) {
        this.mfaMethodType = mfaMethodType;
        this.code = code;
        this.isRegistration = isRegistration;
        this.journeyType = journeyType;
        this.profileInformation = profileInformation;
    }

    @SerializedName("mfaMethodType")
    @Expose
    @Required
    private MFAMethodType mfaMethodType;

    @SerializedName("isRegistration")
    @Expose
    private boolean isRegistration;

    public MFAMethodType getMfaMethodType() {
        return mfaMethodType;
    }

    public boolean isRegistration() {
        return isRegistration;
    }
}
