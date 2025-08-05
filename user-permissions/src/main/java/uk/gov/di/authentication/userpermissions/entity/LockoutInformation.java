package uk.gov.di.authentication.userpermissions.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.validation.Required;

public record LockoutInformation(
        @SerializedName("lockType") @Expose @Required String lockType,
        @SerializedName("mfaMethodType") @Expose @Required MFAMethodType mfaMethodType,
        @SerializedName("lockTTL") @Expose @Required Long lockTTL,
        @SerializedName("journeyType") @Expose @Required JourneyType journeyType) {}
