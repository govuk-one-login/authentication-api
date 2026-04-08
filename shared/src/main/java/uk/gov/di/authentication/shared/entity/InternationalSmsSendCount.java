package uk.gov.di.authentication.shared.entity;

import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbAttribute;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbPartitionKey;
import uk.gov.di.authentication.shared.validation.Required;

@DynamoDbBean
public class InternationalSmsSendCount {

    @Required private String phoneNumber;
    @Required private Integer sentCount;

    @DynamoDbPartitionKey
    @DynamoDbAttribute("PhoneNumber")
    public String getPhoneNumber() {
        return phoneNumber;
    }

    public void setPhoneNumber(String phoneNumber) {
        this.phoneNumber = phoneNumber;
    }

    public InternationalSmsSendCount withPhoneNumber(String phoneNumber) {
        this.phoneNumber = phoneNumber;
        return this;
    }

    @DynamoDbAttribute("SentCount")
    public Integer getSentCount() {
        return sentCount;
    }

    public void setSentCount(Integer sentCount) {
        this.sentCount = sentCount;
    }

    public InternationalSmsSendCount withSentCount(Integer sentCount) {
        this.sentCount = sentCount;
        return this;
    }
}
