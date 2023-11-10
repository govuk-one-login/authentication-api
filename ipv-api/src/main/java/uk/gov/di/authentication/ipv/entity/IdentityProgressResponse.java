package uk.gov.di.authentication.ipv.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import com.nimbusds.oauth2.sdk.id.State;
import uk.gov.di.authentication.shared.validation.Required;

import java.net.URI;

public record IdentityProgressResponse(
        @SerializedName("status") @Expose @Required IdentityProgressStatus status,
        @SerializedName("client-name") @Expose @Required String clientName,
        @SerializedName("redirect-uri") @Expose @Required URI redirectUri,
        @SerializedName("state") @Expose @Required State state) {}
