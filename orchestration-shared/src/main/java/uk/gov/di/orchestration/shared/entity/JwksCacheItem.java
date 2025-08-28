package uk.gov.di.orchestration.shared.entity;

import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbAttribute;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbPartitionKey;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbSortKey;

@DynamoDbBean
public class JwksCacheItem {
    private static final String ATTRIBUTE_JWKS_URL = "JwksUrl";
    private static final String ATTRIBUTE_KEY_ID = "KeyId";
    private static final String ATTRIBUTE_KEY_USE = "KeyUse";
    private String jwksUrl;
    private String keyId;
    private String keyUse;

    public JwksCacheItem() {}

    public JwksCacheItem(String jwksUrl, String keyId, String keyUse) {
        this.jwksUrl = jwksUrl;
        this.keyId = keyId;
        this.keyUse = keyUse;
    }

    @DynamoDbPartitionKey
    @DynamoDbAttribute(ATTRIBUTE_JWKS_URL)
    public String getJwksUrl() {
        return jwksUrl;
    }

    public void setJwksUrl(String jwksUrl) {
        this.jwksUrl = jwksUrl;
    }

    public JwksCacheItem withJwksUrl(String jwksUrl) {
        this.jwksUrl = jwksUrl;
        return this;
    }

    @DynamoDbSortKey
    @DynamoDbAttribute(ATTRIBUTE_KEY_ID)
    public String getKeyId() {
        return keyId;
    }

    public void setKeyId(String keyId) {
        this.keyId = keyId;
    }

    public JwksCacheItem withKeyId(String keyId) {
        this.keyId = keyId;
        return this;
    }

    @DynamoDbAttribute(ATTRIBUTE_KEY_USE)
    public String getKeyUse() {
        return keyUse;
    }

    public void setKeyUse(String keyUse) {
        this.keyUse = keyUse;
    }

    public JwksCacheItem withKeyUse(String keyUse) {
        this.keyUse = keyUse;
        return this;
    }

    @Override
    public String toString() {
        return "JwksCacheItem{"
                + "jwksUrl='"
                + jwksUrl
                + '\''
                + ", keyId='"
                + keyId
                + '\''
                + ", keyUse='"
                + keyUse
                + '\''
                + '}';
    }
}
