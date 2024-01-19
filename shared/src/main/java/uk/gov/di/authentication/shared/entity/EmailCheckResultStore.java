package uk.gov.di.authentication.shared.entity;

import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbAttribute;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbPartitionKey;

@DynamoDbBean
public class EmailCheckResultStore {

    public static final String ATTRIBUTE_EMAIL = "Email";
    public static final String ATTRIBUTE_STATUS = "Status";
    public static final String ATTRIBUTE_TIME_TO_EXIST = "TimeToExist";

    private String email;
    private String status;
    private long timeToExist;

    @DynamoDbPartitionKey
    @DynamoDbAttribute(ATTRIBUTE_EMAIL)
    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public EmailCheckResultStore withEmail(String email) {
        this.email = email;
        return this;
    }

    @DynamoDbAttribute(ATTRIBUTE_STATUS)
    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public EmailCheckResultStore withStatus(String status) {
        this.status = status;
        return this;
    }

    @DynamoDbAttribute(ATTRIBUTE_TIME_TO_EXIST)
    public long getTimeToExist() {
        return timeToExist;
    }

    public void setTimeToExist(long timeToExist) {
        this.timeToExist = timeToExist;
    }

    public EmailCheckResultStore withTimeToExist(long timeToExist) {
        this.timeToExist = timeToExist;
        return this;
    }
}
