package uk.gov.di.authentication.frontendapi.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import uk.gov.di.authentication.shared.entity.BaseFrontendRequest;

public class ResetPasswordRequest extends BaseFrontendRequest {

    @Expose
    @SerializedName("useCodeFlow")
    private boolean useCodeFlow = false;

    public ResetPasswordRequest() {}

    public ResetPasswordRequest(String email, boolean useCodeFlow) {
        this.email = email;
        this.useCodeFlow = useCodeFlow;
    }

    public boolean isUseCodeFlow() {
        return useCodeFlow;
    }

    @Override
    public String toString() {
        return "ResetPasswordRequest{" + "email='" + email + '\'' + '}';
    }
}
