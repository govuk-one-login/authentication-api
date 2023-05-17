package uk.gov.di.authentication.shared.entity;

import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbAttribute;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;

@DynamoDbBean
public class AccountRecovery {

    private boolean blocked;
    private String created;
    private String updated;

    @DynamoDbAttribute("Blocked")
    public boolean isBlocked() {
        return blocked;
    }

    public void setBlocked(boolean blocked) {
        this.blocked = blocked;
    }

    public AccountRecovery withBlocked(boolean blocked) {
        this.blocked = blocked;
        return this;
    }

    @DynamoDbAttribute("Created")
    public String getCreated() {
        return created;
    }

    public void setCreated(String created) {
        this.created = created;
    }

    public AccountRecovery withCreated(String created) {
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

    public AccountRecovery withUpdated(String updated) {
        this.updated = updated;
        return this;
    }
}
