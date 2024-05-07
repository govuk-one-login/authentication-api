package uk.gov.di.authentication.frontendapi.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import uk.gov.di.authentication.shared.entity.BaseFrontendRequest;
import uk.gov.di.authentication.shared.validation.Required;

public class ResetPasswordRequest extends BaseFrontendRequest {
    @Required
    @Expose
    @SerializedName("withinForcedPasswordResetJourney")
    protected boolean withinForcedPasswordResetJourney;

    public ResetPasswordRequest() {}

    public ResetPasswordRequest(String email) {
        this.email = email;
    }

    public boolean isWithinForcedPasswordResetJourney() {
        return withinForcedPasswordResetJourney;
    }

    @Override
    public String toString() {
        return "ResetPasswordRequest{"
                + "email='"
                + email
                + "', withinForcedPasswordResetJourney='"
                + withinForcedPasswordResetJourney
                + "'}";
    }
}
