package uk.gov.di.authentication.frontendapi.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import uk.gov.di.authentication.shared.entity.BaseFrontendRequest;
import uk.gov.di.authentication.shared.validation.Required;

public class UpdateProfileRequest extends BaseFrontendRequest {

    @SerializedName("updateProfileType")
    @Expose
    @Required
    private UpdateProfileType updateProfileType;

    public UpdateProfileRequest() {}

    public UpdateProfileRequest(String email, UpdateProfileType updateProfileType) {
        this.email = email;
        this.updateProfileType = updateProfileType;
    }

    public UpdateProfileType getUpdateProfileType() {
        return updateProfileType;
    }
}
