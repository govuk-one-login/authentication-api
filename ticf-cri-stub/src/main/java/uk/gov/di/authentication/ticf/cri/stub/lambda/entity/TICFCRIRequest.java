package uk.gov.di.authentication.ticf.cri.stub.lambda.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

import java.util.List;

public record TICFCRIRequest(
        @Expose @SerializedName("sub") String internalPairwiseId,
        @Expose @SerializedName("vtr") List<String> vtr,
        @Expose @SerializedName("govuk_signin_journey_id") String journeyId,
        @Expose @SerializedName("authenticated") String authenticated,
        @Expose @SerializedName("initial_registration") String initialRegistration,
        @Expose @SerializedName("password_reset") String passwordReset) {}
