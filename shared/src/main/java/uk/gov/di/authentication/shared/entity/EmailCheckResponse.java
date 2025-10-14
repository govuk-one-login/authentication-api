package uk.gov.di.authentication.shared.entity;

import com.google.gson.JsonElement;
import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

public record EmailCheckResponse(
        @Expose @SerializedName("extensions") JsonElement extensions,
        @Expose @SerializedName("restricted") JsonElement restricted) {

    @Override
    public JsonElement extensions() {
        return this.extensions;
    }

    @Override
    public JsonElement restricted() {
        return this.restricted;
    }
}
