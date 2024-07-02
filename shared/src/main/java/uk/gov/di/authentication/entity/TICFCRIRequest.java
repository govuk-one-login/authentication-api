package uk.gov.di.authentication.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import uk.gov.di.authentication.shared.validation.Required;

import java.util.List;

public record TICFCRIRequest(
        @Expose @SerializedName("sub") String internalPairwiseId,
        @Expose @Required List<String> vtr,
        @Expose @Required String govukSigninJourneyId,
        @Expose @Required String authenticated,
        @Expose String initialRegistration,
        @Expose String passwordReset) {

    public static TICFCRIRequest basicTicfCriRequest(
            String internalPairwiseId, List<String> vtr, String journeyId, boolean authenticated) {
        return new TICFCRIRequest(
                internalPairwiseId, vtr, journeyId, authenticated ? "Y" : "N", null, null);
    }
}
