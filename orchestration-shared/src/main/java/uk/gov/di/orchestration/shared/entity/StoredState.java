package uk.gov.di.orchestration.shared.entity;

import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbAttribute;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbPartitionKey;

@DynamoDbBean
public class StoredState {
    private static final String ATTRIBUTE_PREFIXED_SESSION_ID = "PrefixedSessionId";
    private static final String ATTRIBUTE_STATE = "State";
    private static final String ATTRIBUTE_TIME_TO_LIVE = "ttl";

    private String prefixedSessionId;
    private String state;
    private long ttl;

    public StoredState() {}

    public StoredState(String prefixedSessionId) {
        this.prefixedSessionId = prefixedSessionId;
    }

    @DynamoDbPartitionKey
    @DynamoDbAttribute(ATTRIBUTE_PREFIXED_SESSION_ID)
    public String getPrefixedSessionId() {
        return this.prefixedSessionId;
    }

    public void setPrefixedSessionId(String prefixedSessionId) {
        this.prefixedSessionId = prefixedSessionId;
    }

    public StoredState withPrefixedSessionId(String prefixedSessionId) {
        this.prefixedSessionId = prefixedSessionId;
        return this;
    }

    @DynamoDbAttribute(ATTRIBUTE_STATE)
    public String getState() {
        return state;
    }

    public void setState(String state) {
        this.state = state;
    }

    public StoredState withState(String state) {
        this.state = state;
        return this;
    }

    @DynamoDbAttribute(ATTRIBUTE_TIME_TO_LIVE)
    public long getTtl() {
        return ttl;
    }

    public void setTtl(long ttl) {
        this.ttl = ttl;
    }

    public StoredState withTtl(long ttl) {
        this.ttl = ttl;
        return this;
    }
}
