package uk.gov.di.authentication.frontendapi.entity.amc;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import uk.gov.di.authentication.shared.validation.Required;

public record AMCCallbackRequest(
        @Expose @Required String code,
        @Expose @Required String state,
        @Expose @Required @SerializedName("usedRedirectUrl") String usedRedirectUrl) {}
