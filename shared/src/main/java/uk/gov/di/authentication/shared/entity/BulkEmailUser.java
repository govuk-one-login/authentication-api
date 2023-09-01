package uk.gov.di.authentication.shared.entity;

import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbAttribute;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbPartitionKey;

@DynamoDbBean
public class BulkEmailUser {

    private String subjectID;
    private BulkEmailStatus bulkEmailStatus;
    private String updatedAt;

    public BulkEmailUser() {}

    @DynamoDbPartitionKey
    @DynamoDbAttribute("SubjectID")
    public String getSubjectID() {
        return subjectID;
    }

    public void setSubjectID(String subjectID) {
        this.subjectID = subjectID;
    }

    public BulkEmailUser withSubjectID(String subjectID) {
        this.subjectID = subjectID;
        return this;
    }

    @DynamoDbAttribute("BulkEmailStatus")
    public BulkEmailStatus getBulkEmailStatus() {
        return bulkEmailStatus;
    }

    public void setBulkEmailStatus(BulkEmailStatus bulkEmailStatus) {
        this.bulkEmailStatus = bulkEmailStatus;
    }

    public BulkEmailUser withBulkEmailStatus(BulkEmailStatus bulkEmailStatus) {
        this.bulkEmailStatus = bulkEmailStatus;
        return this;
    }

    @DynamoDbAttribute("UpdatedAt")
    public String getUpdatedAt() {
        return updatedAt;
    }

    public void setUpdatedAt(String timestamp) {
        this.updatedAt = timestamp;
    }

    public BulkEmailUser withUpdatedAt(String timestamp) {
        this.updatedAt = timestamp;
        return this;
    }
}
