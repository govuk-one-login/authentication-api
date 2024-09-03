package uk.gov.di.authentication.frontendapi.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

public record StartRequest(
        @Expose @SerializedName("previous-session-id") String previousSessionId) {}
