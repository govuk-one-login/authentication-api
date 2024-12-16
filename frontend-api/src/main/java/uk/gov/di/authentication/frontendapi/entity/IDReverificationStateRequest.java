package uk.gov.di.authentication.frontendapi.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

public record IDReverificationStateRequest(
        @Expose @SerializedName("authenticationState") String authenticationState) {}
