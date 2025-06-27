package uk.gov.di.orchestration.shared.entity;

import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbAttribute;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbPartitionKey;

@DynamoDbBean
public class StateItem {
    public static final String ATTRIBUTE_PREFIXED_SESSION_ID = "PrefixedSessionId";
    public static final String ATTRIBUTE_STATE = "State";
    public static final String ATTRIBUTE_TTL = "ttl";
    private String prefixedSessionId;
    private String state;
    private long timeToLive;

    public StateItem() {}

    public StateItem(String prefixedSessionId) {
        this.prefixedSessionId = prefixedSessionId;
    }

    @DynamoDbPartitionKey
    @DynamoDbAttribute(ATTRIBUTE_PREFIXED_SESSION_ID)
    public String getPrefixedSessionId() {
        return prefixedSessionId;
    }

    public void setPrefixedSessionId(String prefixedSessionId) {
        this.prefixedSessionId = prefixedSessionId;
    }

    public StateItem withPrefixedSessionId(String prefixedSessionId) {
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

    public StateItem withState(String state) {
        this.state = state;
        return this;
    }

    @DynamoDbAttribute(ATTRIBUTE_TTL)
    public long getTimeToLive() {
        return timeToLive;
    }

    public void setTimeToLive(long timeToLive) {
        this.timeToLive = timeToLive;
    }

    public StateItem withTimeToLive(long timeToLive) {
        this.timeToLive = timeToLive;
        return this;
    }
}
