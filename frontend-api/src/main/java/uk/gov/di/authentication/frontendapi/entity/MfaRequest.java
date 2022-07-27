package uk.gov.di.authentication.frontendapi.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import uk.gov.di.authentication.shared.entity.BaseFrontendRequest;

public class MfaRequest extends BaseFrontendRequest {
    @Expose
    @SerializedName("isResendCodeRequest")
    private boolean isResendCodeRequest = false;

    public MfaRequest() {}

    public MfaRequest(String email, boolean isResendCodeRequest) {
        this.email = email;
        this.isResendCodeRequest = isResendCodeRequest;
    }

    public boolean isResendCodeRequest() {
        return isResendCodeRequest;
    }
}
