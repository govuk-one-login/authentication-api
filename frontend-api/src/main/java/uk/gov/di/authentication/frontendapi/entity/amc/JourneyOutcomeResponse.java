package uk.gov.di.authentication.frontendapi.entity.amc;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

import java.util.List;

public record JourneyOutcomeResponse(
        @Expose String scope, @Expose boolean success, @Expose List<Action> actions) {

    public record Action(
            @Expose String action, @Expose boolean success, @Expose ActionDetails details) {}

    public record ActionDetails(@Expose Error error) {}

    public record Error(
            @Expose int code, @Expose @SerializedName("description") String description) {}
}
