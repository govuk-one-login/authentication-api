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

    @SerializedName("profileInformation")
    @Expose
    @Required
    private String profileInformation;

    public UpdateProfileRequest() {}

    public UpdateProfileRequest(
            String email, UpdateProfileType updateProfileType, String profileInformation) {
        this.email = email;
        this.updateProfileType = updateProfileType;
        this.profileInformation = profileInformation;
    }

    public UpdateProfileType getUpdateProfileType() {
        return updateProfileType;
    }

    public String getProfileInformation() {
        return profileInformation;
    }
}
