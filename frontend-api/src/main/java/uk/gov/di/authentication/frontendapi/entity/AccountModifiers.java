package uk.gov.di.authentication.frontendapi.entity;

import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbAttribute;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbPartitionKey;

@DynamoDbBean
public class AccountModifiers {

    private String internalCommonSubjectIdentifier;
    private String created;
    private String updated;
    private AccountRecovery accountRecovery;

    @DynamoDbPartitionKey
    @DynamoDbAttribute("InternalCommonSubjectIdentifier")
    public String getInternalCommonSubjectIdentifier() {
        return internalCommonSubjectIdentifier;
    }

    public void setInternalCommonSubjectIdentifier(String internalCommonSubjectIdentifier) {
        this.internalCommonSubjectIdentifier = internalCommonSubjectIdentifier;
    }

    public AccountModifiers withInternalCommonSubjectIdentifier(
            String internalCommonSubjectIdentifier) {
        this.internalCommonSubjectIdentifier = internalCommonSubjectIdentifier;
        return this;
    }

    @DynamoDbAttribute("AccountRecovery")
    public AccountRecovery getAccountRecovery() {
        return accountRecovery;
    }

    public void setAccountRecovery(AccountRecovery accountRecovery) {
        this.accountRecovery = accountRecovery;
    }

    public AccountModifiers withAccountRecovery(AccountRecovery accountRecovery) {
        this.accountRecovery = accountRecovery;
        return this;
    }

    @DynamoDbAttribute("Created")
    public String getCreated() {
        return created;
    }

    public void setCreated(String created) {
        this.created = created;
    }

    public AccountModifiers withCreated(String created) {
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

    public AccountModifiers withUpdated(String updated) {
        this.updated = updated;
        return this;
    }
}
