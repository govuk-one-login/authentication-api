package uk.gov.di.authentication.frontendapi.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import com.nimbusds.oauth2.sdk.id.State;

import java.net.URI;
import java.util.List;

public record ClientStartInfo(
        @SerializedName("clientName") @Expose String clientName,
        @SerializedName("scopes") @Expose List<String> scopes,
        @SerializedName("serviceType") @Expose String serviceType,
        @SerializedName("cookieConsentShared") @Expose boolean cookieConsentShared,
        @SerializedName("redirectUri") @Expose URI redirectUri,
        @SerializedName("state") @Expose State state,
        @SerializedName("isOneLoginService") @Expose boolean isOneLoginService) {}
