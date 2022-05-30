package uk.gov.di.authentication.frontendapi.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import uk.gov.di.authentication.shared.validation.Required;

public class SignUpResponse {

    @SerializedName("consentRequired")
    @Expose
    @Required
    private boolean consentRequired;

    public SignUpResponse() {}

    public SignUpResponse(boolean consentRequired) {
        this.consentRequired = consentRequired;
    }

    public boolean isConsentRequired() {
        return consentRequired;
    }
}
