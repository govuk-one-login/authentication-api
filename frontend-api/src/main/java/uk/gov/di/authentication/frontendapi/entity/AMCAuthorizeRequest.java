package uk.gov.di.authentication.frontendapi.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import uk.gov.di.authentication.shared.validation.Required;

public record AMCAuthorizeRequest(
        @Expose @Required @SerializedName("email") String email,
        @Expose @Required @SerializedName("journeyType") AMCJourneyType amcJourneyType) {}
