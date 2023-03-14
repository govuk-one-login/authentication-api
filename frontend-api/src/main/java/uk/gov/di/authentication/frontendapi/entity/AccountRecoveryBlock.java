package uk.gov.di.authentication.frontendapi.entity;

import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbAttribute;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbPartitionKey;

@DynamoDbBean
public class AccountRecoveryBlock {

    private String email;
    private long timeToExist;

    public AccountRecoveryBlock() {}

    @DynamoDbPartitionKey
    @DynamoDbAttribute("Email")
    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public AccountRecoveryBlock withEmail(String email) {
        this.email = email;
        return this;
    }

    @DynamoDbAttribute("TimeToExist")
    public long getTimeToExist() {
        return timeToExist;
    }

    public void setTimeToExist(long timeToExist) {
        this.timeToExist = timeToExist;
    }

    public AccountRecoveryBlock withTimeToExist(long timeToExist) {
        this.timeToExist = timeToExist;
        return this;
    }
}
