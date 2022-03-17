package uk.gov.di.authentication.shared.entity;

import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBAttribute;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBDocument;
import com.amazonaws.services.dynamodbv2.model.AttributeValue;

import java.util.Map;
import java.util.Objects;
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

    AttributeValue toAttributeValue() {
        return new AttributeValue()
                .withM(
                        Map.ofEntries(
                                Map.entry("ClientId", new AttributeValue(getClientId())),
                                Map.entry(
                                        "UpdatedTimestamp",
                                        new AttributeValue(getUpdatedTimestamp())),
                                Map.entry("Claims", new AttributeValue().withSS(getClaims()))));
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ClientConsent that = (ClientConsent) o;
        return Objects.equals(clientId, that.clientId)
                && Objects.equals(updatedTimestamp, that.updatedTimestamp)
                && Objects.equals(claims, that.claims);
    }

    @Override
    public int hashCode() {
        return Objects.hash(clientId, updatedTimestamp, claims);
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
