package uk.gov.di.authentication.shared.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import uk.gov.di.authentication.shared.validation.Required;

public record EmailCheckResultSqsMessage(
        @Expose @SerializedName("Email") @Required String email,
        @Expose @SerializedName("Status") @Required EmailCheckResultStatus emailCheckResultStatus,
        @Expose @SerializedName("TimeToExist") @Required long timeToExist,
        @Expose @SerializedName("ReferenceNumber") @Required String referenceNumber) {}
