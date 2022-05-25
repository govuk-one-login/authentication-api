package uk.gov.di.authentication.frontendapi.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import jakarta.validation.constraints.NotNull;

public class SignUpResponse {

    @SerializedName("consentRequired")
    @Expose
    @NotNull
    private boolean consentRequired;

    public SignUpResponse() {}

    public SignUpResponse(boolean consentRequired) {
        this.consentRequired = consentRequired;
    }

    public boolean isConsentRequired() {
        return consentRequired;
    }
}
