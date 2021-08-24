package uk.gov.di.entity;

import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBAttribute;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBDocument;

import java.time.LocalDateTime;
import java.util.Set;

@DynamoDBDocument
public class ClientConsent {

    private String clientId;
    private String updatedTimestamp;
    private Set<String> claims;

    public ClientConsent() {}

    public ClientConsent(String clientId, Set<String> claims, String updatedTimestamp) {
        this.clientId = clientId;
        this.claims = claims;
        this.updatedTimestamp = updatedTimestamp;
    }

    @DynamoDBAttribute(attributeName = "ClientId")
    public String getClientId() {
        return clientId;
    }

    @DynamoDBAttribute(attributeName = "UpdatedTimestamp")
    public String getUpdatedTimestamp() {
        return updatedTimestamp;
    }

    @DynamoDBAttribute(attributeName = "Claims")
    public Set<String> getClaims() {
        return claims;
    }

    public ClientConsent setClaims(Set<String> claims) {
        this.claims = claims;
        this.updatedTimestamp = LocalDateTime.now().toString();
        return this;
    }

    public ClientConsent setClientId(String clientId) {
        this.clientId = clientId;
        return this;
    }

    public ClientConsent setUpdatedTimestamp(String updatedTimestamp) {
        this.updatedTimestamp = updatedTimestamp;
        return this;
    }

    @Override
    public String toString() {
        return "ClientConsent{"
                + "clientId='"
                + clientId
                + '\''
                + ", updatedTimestamp='"
                + updatedTimestamp
                + '\''
                + ", claims="
                + claims
                + '}';
    }
}
