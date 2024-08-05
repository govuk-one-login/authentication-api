package uk.gov.di.authentication.frontendapi.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

public record MfaResetResponse(@Expose @SerializedName("authorize_url") String authorizeUrl) {}
