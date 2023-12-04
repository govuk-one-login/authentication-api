package uk.gov.di.authentication.frontendapi.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import uk.gov.di.authentication.shared.entity.BaseFrontendRequest;
import uk.gov.di.authentication.shared.entity.JourneyType;

public class MfaRequest extends BaseFrontendRequest {
    @Expose
    @SerializedName("isResendCodeRequest")
    private boolean isResendCodeRequest = false;

    @Expose
    @SerializedName("journeyType")
    private JourneyType journeyType;

    public MfaRequest() {}

    public MfaRequest(String email, boolean isResendCodeRequest) {
        this.email = email;
        this.isResendCodeRequest = isResendCodeRequest;
        this.journeyType = JourneyType.SIGN_IN;
    }

    public MfaRequest(String email, boolean isResendCodeRequest, JourneyType journeyType) {
        this.email = email;
        this.isResendCodeRequest = isResendCodeRequest;
        this.journeyType = journeyType;
    }

    public boolean isResendCodeRequest() {
        return isResendCodeRequest;
    }

    public JourneyType getJourneyType() {
        return journeyType;
    }
}
