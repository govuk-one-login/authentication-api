package uk.gov.di.authentication.frontendapi.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

public record IDReverificationStateResponse(
        @Expose @SerializedName("orchestrationRedirectUrl") String orchestrationRedirectUrl) {}
