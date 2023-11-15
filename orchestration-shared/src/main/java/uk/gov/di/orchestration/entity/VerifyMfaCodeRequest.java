package uk.gov.di.orchestration.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import uk.gov.di.orchestration.shared.entity.JourneyType;
import uk.gov.di.orchestration.shared.entity.MFAMethodType;
import uk.gov.di.orchestration.shared.validation.Required;

public class VerifyMfaCodeRequest extends CodeRequest {

    public VerifyMfaCodeRequest() {}

    public VerifyMfaCodeRequest(MFAMethodType mfaMethodType, String code, JourneyType journeyType) {
        this(mfaMethodType, code, journeyType, null);
    }

    public VerifyMfaCodeRequest(
            MFAMethodType mfaMethodType,
            String code,
            JourneyType journeyType,
            String profileInformation) {
        this.mfaMethodType = mfaMethodType;
        this.code = code;
        this.journeyType = journeyType;
        this.profileInformation = profileInformation;
    }

    @SerializedName("mfaMethodType")
    @Expose
    @Required
    private MFAMethodType mfaMethodType;

    public MFAMethodType getMfaMethodType() {
        return mfaMethodType;
    }
}
