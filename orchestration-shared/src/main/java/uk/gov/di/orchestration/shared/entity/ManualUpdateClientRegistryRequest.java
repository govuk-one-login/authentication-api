package uk.gov.di.orchestration.shared.entity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import uk.gov.di.orchestration.shared.validation.Required;

public class ManualUpdateClientRegistryRequest {

    @SerializedName("client_id")
    @Expose
    @Required
    private String clientId;

    @SerializedName("rate_limit")
    @Expose
    private String rateLimit;

    public ManualUpdateClientRegistryRequest() {}

    public ManualUpdateClientRegistryRequest(String clientId, String rateLimit) {
        this.clientId = clientId;
        this.rateLimit = rateLimit;
    }

    public String getClientId() {
        return clientId;
    }

    public String getClientRateLimit() {
        return rateLimit;
    }

    public ManualUpdateClientRegistryRequest setClientId(String clientId) {
        this.clientId = clientId;
        return this;
    }

    public ManualUpdateClientRegistryRequest setClientRateLimit(String rateLimit) {
        this.rateLimit = rateLimit;
        return this;
    }
}
