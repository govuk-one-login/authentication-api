package uk.gov.di.accountmanagement.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import uk.gov.di.authentication.shared.validation.Required;

public record UpdatePhoneNumberRequest(
        @Expose @Required String email,
        @Expose @SerializedName("phoneNumber") @Required String phoneNumber,
        @Expose @Required String otp) {}
