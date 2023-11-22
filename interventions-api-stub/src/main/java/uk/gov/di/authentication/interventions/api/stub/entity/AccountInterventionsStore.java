package uk.gov.di.authentication.interventions.api.stub.entity;

import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbAttribute;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbPartitionKey;

@DynamoDbBean
public class AccountInterventionsStore {
    private String pairwiseId;
    private boolean blocked = false;
    private boolean suspended = false;
    private boolean reproveIdentity = false;
    private boolean resetPassword = false;

    @DynamoDbPartitionKey
    @DynamoDbAttribute("InternalPairwiseId")
    public String getPairwiseId() {
        return pairwiseId;
    }

    public void setPairwiseId(String pairwiseId) {
        this.pairwiseId = pairwiseId;
    }

    public AccountInterventionsStore withPairwiseId(String pairwiseId) {
        this.pairwiseId = pairwiseId;
        return this;
    }

    @DynamoDbAttribute("Blocked")
    public boolean isBlocked() {
        return blocked;
    }

    public void setBlocked(boolean blocked) {
        this.blocked = blocked;
    }

    public AccountInterventionsStore withBlocked(boolean blocked) {
        this.blocked = blocked;
        return this;
    }

    @DynamoDbAttribute("Suspended")
    public boolean isSuspended() {
        return suspended;
    }

    public void setSuspended(boolean suspended) {
        this.suspended = suspended;
    }

    public AccountInterventionsStore withSuspended(boolean suspended) {
        this.suspended = suspended;
        return this;
    }

    @DynamoDbAttribute("ReproveIdentity")
    public boolean isReproveIdentity() {
        return reproveIdentity;
    }

    public void setReproveIdentity(boolean reproveIdentity) {
        this.reproveIdentity = reproveIdentity;
    }

    public AccountInterventionsStore withReproveIdentity(boolean reproveIdentity) {
        this.reproveIdentity = reproveIdentity;
        return this;
    }

    @DynamoDbAttribute("ResetPassword")
    public boolean isResetPassword() {
        return resetPassword;
    }

    public void setResetPassword(boolean resetPassword) {
        this.resetPassword = resetPassword;
    }

    public AccountInterventionsStore withResetPassword(boolean resetPassword) {
        this.resetPassword = resetPassword;
        return this;
    }
}
