package uk.gov.di.authentication.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.validation.Required;

import java.util.UUID;

public record PendingEmailCheckRequest(
        @SerializedName("userId") @Expose @Required String userId,
        @SerializedName("requestReference") @Expose @Required UUID requestReference,
        @SerializedName("emailAddress") @Expose @Required String emailAddress,
        @SerializedName("userSessionId") @Expose @Required String userSessionId,
        @SerializedName("govukSigninJourneyId") @Expose @Required String govukSigninJourneyId,
        @SerializedName("persistentSessionId") @Expose @Required String persistentSessionId,
        @SerializedName("ipAddress") @Expose @Required String ipAddress,
        @SerializedName("journeyType") @Expose @Required JourneyType journeyType,
        @SerializedName("timeOfInitialRequest") @Expose @Required Long timeOfInitialRequest,
        @SerializedName("isTestUserRequest") @Expose @Required Boolean isTestUserRequest) {}
