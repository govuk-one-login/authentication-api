package uk.gov.di.authentication.shared.entity;

import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbAttribute;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbPartitionKey;
import uk.gov.di.authentication.shared.validation.Required;

@DynamoDbBean
public class AuthenticationAttempts {

    @Required private String attemptIdentifier;
    @Required private String authenticationMethod;
    @Required private String code;
    @Required private Integer count;
    private String created;
    private String updated;
    private long timeToLive;
    private String journeyType;

    @DynamoDbPartitionKey
    @DynamoDbAttribute("AttemptIdentifier")
    public String getAttemptIdentifier() {
        return attemptIdentifier;
    }

    public void setAttemptIdentifier(String attemptIdentifier) {
        this.attemptIdentifier = attemptIdentifier;
    }

    public AuthenticationAttempts withAttemptIdentifier(String attemptIdentifier) {
        this.attemptIdentifier = attemptIdentifier;
        return this;
    }

    @DynamoDbAttribute("JourneyType")
    public String getJourneyType() {
        return journeyType;
    }

    public void setJourneyType(String journeyType) {
        this.journeyType = journeyType;
    }

    public AuthenticationAttempts withJourneyType(String journeyType) {
        this.journeyType = journeyType;
        return this;
    }

    @DynamoDbAttribute("AuthenticationMethod")
    public String getAuthenticationMethod() {
        return authenticationMethod;
    }

    public void setAuthenticationMethod(String authenticationMethod) {
        this.authenticationMethod = authenticationMethod;
    }

    public AuthenticationAttempts withAuthenticationMethod(String authenticationMethod) {
        this.authenticationMethod = authenticationMethod;
        return this;
    }

    @DynamoDbAttribute("Code")
    public String getCode() {
        return code;
    }

    public void setCode(String code) {
        this.code = code;
    }

    public AuthenticationAttempts withCode(String code) {
        this.code = code;
        return this;
    }

    @DynamoDbAttribute("Count")
    public Integer getCount() {
        return count;
    }

    public void setCount(Integer count) {
        this.count = count;
    }

    public AuthenticationAttempts withCount(int count) {
        this.count = count;
        return this;
    }

    @DynamoDbAttribute("TimeToLive")
    public long getTimeToLive() {
        return timeToLive;
    }

    public void setTimeToLive(long timeToLive) {
        this.timeToLive = timeToLive;
    }

    public AuthenticationAttempts withTimeToLive(long timeToLive) {
        this.timeToLive = timeToLive;
        return this;
    }

    @DynamoDbAttribute("Created")
    public String getCreated() {
        return created;
    }

    public void setCreated(String created) {
        this.created = created;
    }

    public AuthenticationAttempts withCreated(String created) {
        this.created = created;
        return this;
    }

    @DynamoDbAttribute("Updated")
    public String getUpdated() {
        return updated;
    }

    public void setUpdated(String updated) {
        this.updated = updated;
    }

    public AuthenticationAttempts withUpdated(String updated) {
        this.updated = updated;
        return this;
    }
}
