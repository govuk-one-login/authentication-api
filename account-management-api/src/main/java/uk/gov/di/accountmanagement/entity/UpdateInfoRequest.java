package uk.gov.di.accountmanagement.entity;

import com.fasterxml.jackson.annotation.JsonProperty;

public class UpdateInfoRequest {

    private final UpdateInfoType updateInfoType;
    private final String existingProfileAttribute;
    private final String replacementProfileAttribute;

    public UpdateInfoRequest(
            @JsonProperty(required = true, value = "updateInfoType") UpdateInfoType updateInfoType,
            @JsonProperty(required = true, value = "existingProfileAttribute")
                    String existingProfileAttribute,
            @JsonProperty(required = true, value = "replacementProfileAttribute")
                    String replacementProfileAttribute) {
        this.updateInfoType = updateInfoType;
        this.existingProfileAttribute = existingProfileAttribute;
        this.replacementProfileAttribute = replacementProfileAttribute;
    }

    public UpdateInfoType getUpdateInfoType() {
        return updateInfoType;
    }

    public String getExistingProfileAttribute() {
        return existingProfileAttribute;
    }

    public String getReplacementProfileAttribute() {
        return replacementProfileAttribute;
    }
}
