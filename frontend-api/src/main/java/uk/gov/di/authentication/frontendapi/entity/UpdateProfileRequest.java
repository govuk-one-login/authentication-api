package uk.gov.di.authentication.frontendapi.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import jakarta.validation.constraints.NotNull;
import uk.gov.di.authentication.shared.entity.BaseFrontendRequest;

public class UpdateProfileRequest extends BaseFrontendRequest {

    @SerializedName("updateProfileType")
    @Expose
    @NotNull
    private UpdateProfileType updateProfileType;

    @SerializedName("profileInformation")
    @Expose
    @NotNull
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
