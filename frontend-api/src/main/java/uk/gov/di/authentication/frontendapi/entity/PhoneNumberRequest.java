package uk.gov.di.authentication.frontendapi.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import uk.gov.di.authentication.shared.entity.JourneyType;

public class PhoneNumberRequest {
    @Expose
    @SerializedName("phoneNumberVerified")
    private boolean phoneNumberVerified;

    @Expose
    @SerializedName("phoneNumber")
    private String phoneNumber;

    @Expose
    @SerializedName("updatedPhoneNumber")
    private boolean updatedPhoneNumber;

    @Expose
    @SerializedName("journeyType")
    private JourneyType journeyType;

    @Expose
    @SerializedName("internalCommonSubjectIdentifier")
    private String internalCommonSubjectIdentifier;

    public PhoneNumberRequest(
            boolean phoneNumberVerified,
            String phoneNumber,
            boolean updatedPhoneNumber,
            JourneyType journeyType,
            String internalCommonSubjectIdentifier) {
        this.phoneNumberVerified = phoneNumberVerified;
        this.phoneNumber = phoneNumber;
        this.updatedPhoneNumber = updatedPhoneNumber;
        this.journeyType = journeyType;
        this.internalCommonSubjectIdentifier = internalCommonSubjectIdentifier;
    }

    public boolean isPhoneNumberVerified() {
        return phoneNumberVerified;
    }

    public String getPhoneNumber() {
        return phoneNumber;
    }

    public boolean isUpdatedPhoneNumber() {
        return updatedPhoneNumber;
    }

    public JourneyType getJourneyType() {
        return journeyType;
    }

    public String getInternalCommonSubjectIdentifier() {
        return internalCommonSubjectIdentifier;
    }
}
