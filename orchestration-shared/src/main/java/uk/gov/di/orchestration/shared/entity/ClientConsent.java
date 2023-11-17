package uk.gov.di.orchestration.shared.entity;

import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbAttribute;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;

import java.util.Map;
import java.util.Objects;
import java.util.Set;

@DynamoDbBean
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

    @DynamoDbAttribute("ClientId")
    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public ClientConsent withClientId(String clientId) {
        this.clientId = clientId;
        return this;
    }

    @DynamoDbAttribute("UpdatedTimestamp")
    public String getUpdatedTimestamp() {
        return updatedTimestamp;
    }

    public void setUpdatedTimestamp(String updatedTimestamp) {
        this.updatedTimestamp = updatedTimestamp;
    }

    public ClientConsent withUpdatedTimestamp(String updatedTimestamp) {
        this.updatedTimestamp = updatedTimestamp;
        return this;
    }

    @DynamoDbAttribute("Claims")
    public Set<String> getClaims() {
        return claims;
    }

    public void setClaims(Set<String> claims) {
        this.claims = claims;
    }

    public ClientConsent withClaims(Set<String> claims) {
        this.claims = claims;
        return this;
    }

    AttributeValue toAttributeValue() {
        return AttributeValue.builder()
                .m(
                        Map.ofEntries(
                                Map.entry("ClientId", AttributeValue.fromS(getClientId())),
                                Map.entry(
                                        "UpdatedTimestamp",
                                        AttributeValue.fromS(getUpdatedTimestamp())),
                                Map.entry(
                                        "Claims",
                                        AttributeValue.builder().ss(getClaims()).build())))
                .build();
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
