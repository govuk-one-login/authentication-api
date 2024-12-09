package uk.gov.di.authentication.shared.entity;

import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbAttribute;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbPartitionKey;

@DynamoDbBean
public class IDReverificationState {
    private static final String ATTRIBUTE_AUTHENTICATION_STATE = "AuthenticationState";
    private static final String ATTRIBUTE_ORCHESTRATION_REDIRECT_URL = "OrchestrationRedirectUrl";
    private static final String ATTRIBUTE_TIME_TO_EXIST = "TimeToExist";

    private String authenticationState;
    private String orchestrationRedirectUrl;
    private long timeToExist;

    @DynamoDbPartitionKey
    @DynamoDbAttribute(ATTRIBUTE_AUTHENTICATION_STATE)
    public String getAuthenticationState() {
        return authenticationState;
    }

    public IDReverificationState withAuthenticationState(String authenticationState) {
        this.authenticationState = authenticationState;
        return this;
    }

    @DynamoDbAttribute(ATTRIBUTE_ORCHESTRATION_REDIRECT_URL)
    public String getOrchestrationRedirectUrl() {
        return orchestrationRedirectUrl;
    }

    public IDReverificationState withOrchestrationRedirectUrl(String orchestrationRedirectUrl) {
        this.orchestrationRedirectUrl = orchestrationRedirectUrl;
        return this;
    }

    @DynamoDbAttribute(ATTRIBUTE_TIME_TO_EXIST)
    public long getTimeToExist() {
        return timeToExist;
    }

    public void setTimeToExist(long timeToExist) {
        this.timeToExist = timeToExist;
    }

    public IDReverificationState withTimeToExist(long timeToExist) {
        this.timeToExist = timeToExist;
        return this;
    }
}
