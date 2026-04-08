package uk.gov.di.authentication.shared.entity;

import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbAttribute;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbPartitionKey;

@DynamoDbBean
public class AMCState {
    public static final String ATTRIBUTE_AUTHENTICATION_STATE = "AuthenticationState";
    public static final String ATTRIBUTE_CLIENT_SESSION_ID = "ClientSessionId";
    public static final String ATTRIBUTE_TIME_TO_EXIST = "TimeToExist";

    private String authenticationState;
    private String clientSessionId;
    private long timeToExist;

    @DynamoDbPartitionKey
    @DynamoDbAttribute(ATTRIBUTE_AUTHENTICATION_STATE)
    public String getAuthenticationState() {
        return authenticationState;
    }

    public void setAuthenticationState(String authenticationState) {
        this.authenticationState = authenticationState;
    }

    public AMCState withAuthenticationState(String authenticationState) {
        this.authenticationState = authenticationState;
        return this;
    }

    @DynamoDbAttribute(ATTRIBUTE_CLIENT_SESSION_ID)
    public String getClientSessionId() {
        return clientSessionId;
    }

    public void setClientSessionId(String clientSessionId) {
        this.clientSessionId = clientSessionId;
    }

    public AMCState withClientSessionId(String journeyId) {
        this.clientSessionId = journeyId;
        return this;
    }

    @DynamoDbAttribute(ATTRIBUTE_TIME_TO_EXIST)
    public long getTimeToExist() {
        return timeToExist;
    }

    public void setTimeToExist(long timeToExist) {
        this.timeToExist = timeToExist;
    }

    public AMCState withTimeToExist(long timeToExist) {
        this.timeToExist = timeToExist;
        return this;
    }
}
