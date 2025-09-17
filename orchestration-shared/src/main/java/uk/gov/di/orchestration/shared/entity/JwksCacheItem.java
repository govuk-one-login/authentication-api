package uk.gov.di.orchestration.shared.entity;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbAttribute;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbPartitionKey;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbSortKey;

@DynamoDbBean
public class JwksCacheItem {
    private static final String ATTRIBUTE_JWKS_URL = "JwksUrl";
    private static final String ATTRIBUTE_KEY_ID = "KeyId";
    private static final String ATTRIBUTE_KEY_USE = "KeyUse";
    private static final String ATTRIBUTE_KEY = "Key";
    private String jwksUrl;
    private String keyId;
    private String keyUse;
    private String key;
    private long timeToLive;

    public JwksCacheItem() {}

    public JwksCacheItem(String jwksUrl, JWK jwk, long timeToLive, KeyUse keyUse) {
        this.jwksUrl = jwksUrl;
        this.keyId = jwk.getKeyID();
        this.timeToLive = timeToLive;
        this.keyUse = keyUse.getValue();
        this.key = jwk.toJSONString();
    }

    public JwksCacheItem(String jwksUrl, JWK jwk, long timeToLive) {
        this(jwksUrl, jwk, timeToLive, KeyUse.ENCRYPTION);
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

    @DynamoDbAttribute(ATTRIBUTE_KEY)
    public String getKey() {
        return key;
    }

    public void setKey(String key) {
        this.key = key;
    }

    public JwksCacheItem withKey(String key) {
        this.key = key;
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

    @DynamoDbAttribute("ttl")
    public long getTimeToLive() {
        return timeToLive;
    }

    public void setTimeToLive(long timeToLive) {
        this.timeToLive = timeToLive;
    }

    public JwksCacheItem withTimeToLive(long timeToLive) {
        this.timeToLive = timeToLive;
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
