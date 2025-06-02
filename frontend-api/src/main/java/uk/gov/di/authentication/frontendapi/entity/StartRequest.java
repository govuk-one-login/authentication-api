package uk.gov.di.authentication.frontendapi.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

public record StartRequest(
        @Expose @SerializedName("previous-session-id") String previousSessionId,
        @Expose @SerializedName("rp-pairwise-id-for-reauth") String rpPairwiseIdForReauth,
        @Expose @SerializedName("previous-govuk-signin-journey-id")
                String previousGovUkSigninJourneyId,
        @Expose @SerializedName("authenticated") boolean authenticated,
        @Expose @SerializedName("cookie_consent") String cookieConsent,
        @Expose @SerializedName("_ga") String ga,
        @Expose @SerializedName("requested_credential_strength") String requestedCredentialStrength,
        @Expose @SerializedName("requested_level_of_confidence") String requestedLevelOfConfidence,
        @Expose @SerializedName("state") String state,
        @Expose @SerializedName("client_id") String clientId,
        @Expose @SerializedName("redirect_uri") String redirectUri,
        @Expose @SerializedName("scope") String scope,
        @Expose @SerializedName("client_name") String clientName,
        @Expose @SerializedName("service_type") String serviceType,
        @Expose @SerializedName("cookie_consent_shared") boolean isCookieConsentShared,
        @Expose @SerializedName("is_smoke_test") boolean isSmokeTest) {}
