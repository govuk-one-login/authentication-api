package uk.gov.di.authentication.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.validation.Required;

public abstract class CodeRequest {

    @SerializedName("code")
    @Expose
    @Required
    protected String code;

    @SerializedName("profileInformation")
    @Expose
    protected String profileInformation;

    @SerializedName("journeyType")
    @Expose
    @Required
    protected JourneyType journeyType;

    public String getCode() {
        return code;
    }

    public String getProfileInformation() {
        return profileInformation;
    }

    public JourneyType getJourneyType() {
        return journeyType;
    }
}
