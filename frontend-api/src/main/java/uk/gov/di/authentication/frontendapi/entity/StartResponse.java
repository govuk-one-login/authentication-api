package uk.gov.di.authentication.frontendapi.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import uk.gov.di.authentication.shared.validation.Required;

public record StartResponse(
        @SerializedName("user") @Required @Expose UserStartInfo user,
        @SerializedName("client") @Required @Expose ClientStartInfo client) {}
