package uk.gov.di.authentication.ticf.cri.stub.lambda.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

import java.util.List;

public record TICFCRIStubResponse(
        @Expose @SerializedName("intervention") Intervention intervention,
        @Expose @SerializedName("sub") String internalPairwiseId,
        @Expose @SerializedName("govuk_signin_journey_id") String journeyId,
        @Expose @SerializedName("ci") List<String> ci) {
    public record Intervention(
            @Expose @SerializedName("interventionCode") String interventionCode,
            @Expose @SerializedName("interventionReason") String interventionReason) {}
}
