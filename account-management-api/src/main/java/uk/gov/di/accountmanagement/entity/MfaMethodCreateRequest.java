package uk.gov.di.accountmanagement.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import uk.gov.di.authentication.shared.validation.Required;

public record MfaMethodCreateRequest(
        @Expose @SerializedName("mfaMethod") @Required String mfaMethod) {}
