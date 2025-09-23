package uk.gov.di.orchestration.shared.entity;

import com.nimbusds.oauth2.sdk.id.State;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbAttribute;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbPartitionKey;

import java.util.Objects;

@DynamoDbBean
public class CrossBrowserItem {
    private static final String ATTRIBUTE_STATE = "State";
    private static final String ATTRIBUTE_CLIENT_SESSION_ID = "ClientSessionId";
    private static final String ATTRIBUTE_TTL = "ttl";

    private String state;
    private String clientSessionId;
    private long ttl;

    public CrossBrowserItem() {}

    public CrossBrowserItem(State state, String clientSessionId) {
        this.state = state.getValue();
        this.clientSessionId = clientSessionId;
    }

    @DynamoDbPartitionKey
    @DynamoDbAttribute(ATTRIBUTE_STATE)
    public String getState() {
        return state;
    }

    public void setState(String state) {
        this.state = state;
    }

    public CrossBrowserItem withState(String state) {
        this.state = state;
        return this;
    }

    @DynamoDbAttribute(ATTRIBUTE_CLIENT_SESSION_ID)
    public String getClientSessionId() {
        return clientSessionId;
    }

    public void setClientSessionId(String clientSessionId) {
        this.clientSessionId = clientSessionId;
    }

    public CrossBrowserItem withClientSessionId(String clientSessionId) {
        this.clientSessionId = clientSessionId;
        return this;
    }

    @DynamoDbAttribute(ATTRIBUTE_TTL)
    public long getTimeToLive() {
        return ttl;
    }

    public void setTimeToLive(long ttl) {
        this.ttl = ttl;
    }

    public CrossBrowserItem withTimeToLive(long ttl) {
        this.ttl = ttl;
        return this;
    }

    @Override
    public boolean equals(Object o) {
        if (o == null || getClass() != o.getClass()) return false;
        CrossBrowserItem that = (CrossBrowserItem) o;
        return ttl == that.ttl
                && Objects.equals(state, that.state)
                && Objects.equals(clientSessionId, that.clientSessionId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(state, clientSessionId, ttl);
    }
}
