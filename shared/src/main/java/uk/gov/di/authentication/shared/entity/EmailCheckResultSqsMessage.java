package uk.gov.di.authentication.shared.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import uk.gov.di.authentication.shared.validation.Required;

public record EmailCheckResultSqsMessage(
        @Expose @SerializedName("EmailAddress") @Required String emailAddress,
        @Expose @SerializedName("Status") @Required EmailCheckResultStatus status,
        @Expose @SerializedName("TimeToExist") @Required long timeToExist,
        @Expose @SerializedName("RequestReference") @Required String requestReference,
        @Expose @SerializedName("TimeOfInitialRequest") @Required long timeOfInitialRequest,
        @Expose @SerializedName("GovukSigninJourneyId") String govukSigninJourneyId,
        @Expose @SerializedName("EmailCheckResponse") EmailCheckResponse emailCheckResponse) {}
