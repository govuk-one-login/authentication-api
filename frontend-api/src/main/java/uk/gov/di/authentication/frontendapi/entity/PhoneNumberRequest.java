package uk.gov.di.authentication.frontendapi.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import uk.gov.di.authentication.shared.entity.JourneyType;

public record PhoneNumberRequest(
        @Expose @SerializedName("phoneNumberVerified") boolean phoneNumberVerified,
        @Expose @SerializedName("phoneNumber") String phoneNumber,
        @Expose @SerializedName("updatedPhoneNumber") boolean updatedPhoneNumber,
        @Expose @SerializedName("journeyType") JourneyType journeyType,
        @Expose @SerializedName("internalCommonSubjectIdentifier")
                String internalCommonSubjectIdentifier) {}
