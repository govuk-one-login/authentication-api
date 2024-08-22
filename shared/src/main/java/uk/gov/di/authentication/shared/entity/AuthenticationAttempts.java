package uk.gov.di.authentication.shared.entity;

import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbAttribute;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbPartitionKey;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbSortKey;
import uk.gov.di.authentication.shared.validation.Required;

@DynamoDbBean
public class AuthenticationAttempts {

    @Required private String internalSubjectId;
    @Required private String countType;
    @Required private Integer count;
    @Required private String journeyType;

    private String sortKey;
    private String created;
    private String updated;
    private long timeToLive;

    @DynamoDbPartitionKey
    @DynamoDbAttribute("InternalSubjectId")
    public String getInternalSubjectId() {
        return internalSubjectId;
    }

    public void setInternalSubjectId(String internalSubjectId) {
        this.internalSubjectId = internalSubjectId;
    }

    public AuthenticationAttempts withInternalSubjectId(String internalSubjectId) {
        this.internalSubjectId = internalSubjectId;
        return this;
    }

    public void setJourneyType(JourneyType journeyType) {
        this.journeyType = journeyType.getValue();
        sortKey = null;
    }

    public AuthenticationAttempts withJourneyType(JourneyType journeyType) {
        setJourneyType(journeyType);
        return this;
    }

    public void setCountType(CountType countType) {
        this.countType = countType.getValue();
        sortKey = null;
    }

    public AuthenticationAttempts withCountType(CountType countType) {
        setCountType(countType);
        return this;
    }

    @DynamoDbSortKey
    @DynamoDbAttribute("SK")
    public String getSortKey() {
        return sortKey != null ? sortKey : buildSortKey();
    }

    private String buildSortKey() {
        return journeyType + "#" + countType + "#" + "Count";
    }

    public void setSortKey(String sortKey) {
        this.sortKey = sortKey;
        countType = null;
        journeyType = null;
    }

    @DynamoDbAttribute("Count")
    public Integer getCount() {
        return count;
    }

    public void setCount(Integer count) {
        this.count = count;
    }

    public AuthenticationAttempts withCount(int count) {
        this.count = count;
        return this;
    }

    @DynamoDbAttribute("TimeToLive")
    public long getTimeToLive() {
        return timeToLive;
    }

    public void setTimeToLive(long timeToLive) {
        this.timeToLive = timeToLive;
    }

    public AuthenticationAttempts withTimeToLive(long timeToLive) {
        this.timeToLive = timeToLive;
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
