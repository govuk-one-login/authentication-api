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
    private String emailAddressLastUpdated;
    private String emailAddressSource = "AUTH_BACKFILL";
    private String emailAddressSourceId = "UserProfile.Email";
    private String userLastActive;
    private String status = "pending";
    private String statusLastUpdated;
    private String userLastActiveSource = "AUTH_BACKFILL";
    private String userLastActiveSourceId;
    private String userLastActiveUpdated;

    public InactiveAccountTrackerItem() {}

    @DynamoDbPartitionKey
    @DynamoDbAttribute("dateForDeletion")
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
    @DynamoDbAttribute("commonSubjectId")
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

    @DynamoDbAttribute("publicSubjectId")
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

    @DynamoDbAttribute("emailAddress")
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

    @DynamoDbAttribute("emailAddressLastUpdated")
    public String getEmailAddressLastUpdated() {
        return emailAddressLastUpdated;
    }

    public void setEmailAddressLastUpdated(String emailAddressLastUpdated) {
        this.emailAddressLastUpdated = emailAddressLastUpdated;
    }

    public InactiveAccountTrackerItem withEmailAddressLastUpdated(String emailAddressLastUpdated) {
        this.emailAddressLastUpdated = emailAddressLastUpdated;
        return this;
    }

    @DynamoDbAttribute("emailAddressSource")
    public String getEmailAddressSource() {
        return emailAddressSource;
    }

    public void setEmailAddressSource(String emailAddressSource) {
        this.emailAddressSource = emailAddressSource;
    }

    @DynamoDbAttribute("emailAddressSourceId")
    public String getEmailAddressSourceId() {
        return emailAddressSourceId;
    }

    public void setEmailAddressSourceId(String emailAddressSourceId) {
        this.emailAddressSourceId = emailAddressSourceId;
    }

    @DynamoDbAttribute("status")
    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    @DynamoDbAttribute("statusLastUpdated")
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

    @DynamoDbAttribute("userLastActive")
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

    @DynamoDbAttribute("userLastActiveSource")
    public String getUserLastActiveSource() {
        return userLastActiveSource;
    }

    public void setUserLastActiveSource(String userLastActiveSource) {
        this.userLastActiveSource = userLastActiveSource;
    }

    @DynamoDbAttribute("userLastActiveSourceId")
    public String getUserLastActiveSourceId() {
        return userLastActiveSourceId;
    }

    public void setUserLastActiveSourceId(String userLastActiveSourceId) {
        this.userLastActiveSourceId = userLastActiveSourceId;
    }

    public InactiveAccountTrackerItem withUserLastActiveSourceId(String userLastActiveSourceId) {
        this.userLastActiveSourceId = userLastActiveSourceId;
        return this;
    }

    @DynamoDbAttribute("userLastActiveUpdated")
    public String getUserLastActiveUpdated() {
        return userLastActiveUpdated;
    }

    public void setUserLastActiveUpdated(String userLastActiveUpdated) {
        this.userLastActiveUpdated = userLastActiveUpdated;
    }

    public InactiveAccountTrackerItem withUserLastActiveUpdated(String userLastActiveUpdated) {
        this.userLastActiveUpdated = userLastActiveUpdated;
        return this;
    }
}
