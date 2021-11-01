package uk.gov.di.authentication.frontendapi.entity;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotNull;

public class UpdateProfileRequest extends BaseFrontendRequest {

    @JsonProperty(required = true, value = "updateProfileType")
    @NotNull
    private UpdateProfileType updateProfileType;

    @JsonProperty(required = true, value = "profileInformation")
    @NotNull
    private String profileInformation;

    public UpdateProfileType getUpdateProfileType() {
        return updateProfileType;
    }

    public String getProfileInformation() {
        return profileInformation;
    }
}
