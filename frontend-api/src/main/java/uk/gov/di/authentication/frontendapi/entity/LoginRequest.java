package uk.gov.di.authentication.frontendapi.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import uk.gov.di.authentication.shared.entity.BaseFrontendRequest;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.validation.Required;

public class LoginRequest extends BaseFrontendRequest {

    @Expose @Required private String password;

    @SerializedName("journeyType")
    @Expose
    protected JourneyType journeyType;

    public LoginRequest() {}

    public LoginRequest(String email, String password, JourneyType journeyType) {
        this.email = email;
        this.password = password;
        this.journeyType = journeyType;
    }

    public String getPassword() {
        return password;
    }

    public JourneyType getJourneyType() {
        return journeyType;
    }
}
