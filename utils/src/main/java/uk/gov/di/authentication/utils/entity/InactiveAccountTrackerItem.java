package uk.gov.di.authentication.utils.entity;

import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbAttribute;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbPartitionKey;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbSortKey;

@DynamoDbBean
public class InactiveAccountTrackerItem {

    private String dateForDeletion;
    private String commonSubjectId;
    private String publicSubjectId;
    private String emailAddress;
    private String userLastActive;
    private String status = "pending";
    private String statusLastUpdated;
    private String source = "AUTH_BACKFILL";
    private String sourceId;

    public InactiveAccountTrackerItem() {}

    @DynamoDbPartitionKey
    @DynamoDbAttribute("DateForDeletion")
    public String getDateForDeletion() {
        return dateForDeletion;
    }

    public void setDateForDeletion(String dateForDeletion) {
        this.dateForDeletion = dateForDeletion;
    }

    public InactiveAccountTrackerItem withDateForDeletion(String dateForDeletion) {
        this.dateForDeletion = dateForDeletion;
        return this;
    }

    @DynamoDbSortKey
    @DynamoDbAttribute("CommonSubjectId")
    public String getCommonSubjectId() {
        return commonSubjectId;
    }

    public void setCommonSubjectId(String commonSubjectId) {
        this.commonSubjectId = commonSubjectId;
    }

    public InactiveAccountTrackerItem withCommonSubjectId(String commonSubjectId) {
        this.commonSubjectId = commonSubjectId;
        return this;
    }

    @DynamoDbAttribute("PublicSubjectId")
    public String getPublicSubjectId() {
        return publicSubjectId;
    }

    public void setPublicSubjectId(String publicSubjectId) {
        this.publicSubjectId = publicSubjectId;
    }

    public InactiveAccountTrackerItem withPublicSubjectId(String publicSubjectId) {
        this.publicSubjectId = publicSubjectId;
        return this;
    }

    @DynamoDbAttribute("EmailAddress")
    public String getEmailAddress() {
        return emailAddress;
    }

    public void setEmailAddress(String emailAddress) {
        this.emailAddress = emailAddress;
    }

    public InactiveAccountTrackerItem withEmailAddress(String emailAddress) {
        this.emailAddress = emailAddress;
        return this;
    }

    @DynamoDbAttribute("UserLastActive")
    public String getUserLastActive() {
        return userLastActive;
    }

    public void setUserLastActive(String userLastActive) {
        this.userLastActive = userLastActive;
    }

    public InactiveAccountTrackerItem withUserLastActive(String userLastActive) {
        this.userLastActive = userLastActive;
        return this;
    }

    @DynamoDbAttribute("Status")
    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    @DynamoDbAttribute("StatusLastUpdated")
    public String getStatusLastUpdated() {
        return statusLastUpdated;
    }

    public void setStatusLastUpdated(String statusLastUpdated) {
        this.statusLastUpdated = statusLastUpdated;
    }

    public InactiveAccountTrackerItem withStatusLastUpdated(String statusLastUpdated) {
        this.statusLastUpdated = statusLastUpdated;
        return this;
    }

    @DynamoDbAttribute("Source")
    public String getSource() {
        return source;
    }

    public void setSource(String source) {
        this.source = source;
    }

    @DynamoDbAttribute("SourceId")
    public String getSourceId() {
        return sourceId;
    }

    public void setSourceId(String sourceId) {
        this.sourceId = sourceId;
    }

    public InactiveAccountTrackerItem withSourceId(String sourceId) {
        this.sourceId = sourceId;
        return this;
    }
}
