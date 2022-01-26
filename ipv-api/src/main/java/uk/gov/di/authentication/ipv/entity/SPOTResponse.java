package uk.gov.di.authentication.ipv.entity;

import com.fasterxml.jackson.annotation.JsonProperty;

public class SPOTResponse {

    @JsonProperty private String serializedCredential;

    @JsonProperty private String pairwiseIdentifier;

    public SPOTResponse(
            @JsonProperty(required = true, value = "serializedCredential")
                    String serializedCredential,
            @JsonProperty(required = true, value = "pairwiseIdentifier")
                    String pairwiseIdentifier) {
        this.serializedCredential = serializedCredential;
        this.pairwiseIdentifier = pairwiseIdentifier;
    }

    public String getSerializedCredential() {
        return serializedCredential;
    }

    public String getPairwiseIdentifier() {
        return pairwiseIdentifier;
    }
}
