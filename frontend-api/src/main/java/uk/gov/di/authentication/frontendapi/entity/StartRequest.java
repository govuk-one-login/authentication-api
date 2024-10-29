package uk.gov.di.authentication.frontendapi.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import uk.gov.di.authentication.shared.entity.CredentialTrustLevel;

public record StartRequest(
        @Expose @SerializedName("previous-session-id") String previousSessionId,
        @Expose @SerializedName("rp-pairwise-id-for-reauth") String rpPairwiseIdForReauth,
        @Expose @SerializedName("previous-govuk-signin-journey-id")
                String previousGovUkSigninJourneyId,
        @Expose @SerializedName("current-credential-strength")
                CredentialTrustLevel currentCredentialStrength) {}
