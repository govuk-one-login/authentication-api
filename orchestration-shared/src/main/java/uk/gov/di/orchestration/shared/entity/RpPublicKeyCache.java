package uk.gov.di.orchestration.shared.entity;

import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbAttribute;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbPartitionKey;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbSortKey;

@DynamoDbBean
public class RpPublicKeyCache {

    private String clientId;
    private String keyId;
    private String publicKey;
    private long timeToLive;

    @DynamoDbPartitionKey
    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public RpPublicKeyCache withClientId(String clientId) {
        this.clientId = clientId;
        return this;
    }

    @DynamoDbSortKey
    public String getKeyId() {
        return keyId;
    }

    public void setKeyId(String keyId) {
        this.keyId = keyId;
    }

    public RpPublicKeyCache withKeyId(String keyId) {
        this.keyId = keyId;
        return this;
    }

    @DynamoDbAttribute("publicKey")
    public String getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(String publicKey) {
        this.publicKey = publicKey;
    }

    public RpPublicKeyCache withPublicKey(String publicKey) {
        this.publicKey = publicKey;
        return this;
    }

    @DynamoDbAttribute("ttl")
    public long getTimeToLive() {
        return timeToLive;
    }

    public void setTimeToLive(long timeToLive) {
        this.timeToLive = timeToLive;
    }

    public RpPublicKeyCache withTimeToLive(long timeToLive) {
        this.timeToLive = timeToLive;
        return this;
    }
}
