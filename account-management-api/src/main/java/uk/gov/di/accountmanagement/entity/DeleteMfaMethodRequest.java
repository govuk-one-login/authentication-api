package uk.gov.di.accountmanagement.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import uk.gov.di.authentication.shared.validation.Required;

public record DeleteMfaMethodRequest(
        @Expose @Required String email,
        @Expose @Required String otp,
        @Expose @Required @SerializedName("mfaIdentifier") String mfaIdentifier) {}
