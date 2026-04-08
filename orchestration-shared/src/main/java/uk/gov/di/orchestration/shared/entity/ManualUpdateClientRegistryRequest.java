package uk.gov.di.orchestration.shared.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import uk.gov.di.orchestration.shared.validation.Required;

public record ManualUpdateClientRegistryRequest(
        @SerializedName("client_id") @Expose @Required String clientId,
        @SerializedName("rate_limit") @Expose String rateLimit) {

    @Override
    public String toString() {
        var clientIdString = "ClientId=" + clientId;
        var rateLimitString = rateLimit != null ? ", RateLimit=" + rateLimit : "";
        return clientIdString + rateLimitString;
    }
}
