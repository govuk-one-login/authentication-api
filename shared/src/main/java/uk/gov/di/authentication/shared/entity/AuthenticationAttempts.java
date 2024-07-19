package uk.gov.di.authentication.shared.entity;

import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbAttribute;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbPartitionKey;

@DynamoDbBean
public class AuthenticationAttempts {

    private String attemptIdentifier;
    private String email;
    private String journeyType;
    private String authenticationType;
    private String code;
    private Integer count;
    private long timeToExist;
    private String created;
    private String updated;

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

    @DynamoDbAttribute("Email")
    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    @DynamoDbAttribute("JourneyType")
    public String getJourneyType() {
        return journeyType;
    }

    public void setJourneyType(String journeyType) {
        this.journeyType = journeyType;
    }

    @DynamoDbAttribute("AuthenticationType")
    public String getAuthenticationType() {
        return authenticationType;
    }

    public void setAuthenticationType(String authenticationType) {
        this.authenticationType = authenticationType;
    }

    @DynamoDbAttribute("Code")
    public String getCode() {
        return code;
    }

    public void setCode(String code) {
        this.code = code;
    }

    @DynamoDbAttribute("Count")
    public Integer getCount() {
        return count;
    }

    public void setCount(Integer count) {
        this.count = count;
    }

    @DynamoDbAttribute("TimeToExist")
    public long getTimeToExist() {
        return timeToExist;
    }

    public void setTimeToExist(long timeToExist) {
        this.timeToExist = timeToExist;
    }

    public AuthenticationAttempts withTimeToExist(long timeToExist) {
        this.timeToExist = timeToExist;
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
