package uk.gov.di.authentication.shared.entity;

import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbAttribute;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbPartitionKey;

@DynamoDbBean
public class AuthCodeStore {

    public static final String ATTRIBUTE_SUBJECT_ID = "SubjectID";
    public static final String ATTRIBUTE_AUTH_CODE = "AuthCode";
    public static final String ATTRIBUTE_REQUESTED_SCOPES_CLAIMS = "RequestedScopes/Claims";
    public static final String ATTRIBUTE_TIME_TO_EXIST = "TimeToExist";
    public static final String ATTRIBUTE_HAS_BEEN_USED = "HasBeenUsed";

    private String subjectID;
    private String authCode;
    private String requestedScopeClaims;
    private long timeToExist;
    private boolean hasBeenUsed;

    public AuthCodeStore() {}

    @DynamoDbPartitionKey
    @DynamoDbAttribute(ATTRIBUTE_SUBJECT_ID)
    public String getSubjectID() {
        return subjectID;
    }

    public void setSubjectID(String subjectID) {
        this.subjectID = subjectID;
    }

    public AuthCodeStore withSubjectID(String subjectID) {
        this.subjectID = subjectID;
        return this;
    }

    @DynamoDbAttribute(ATTRIBUTE_AUTH_CODE)
    public String getAuthCode() {
        return authCode;
    }

    public void setAuthCode(String authCode) {
        this.authCode = authCode;
    }

    public AuthCodeStore withAuthCode(String authCode) {
        this.authCode = authCode;
        return this;
    }

    @DynamoDbAttribute(ATTRIBUTE_REQUESTED_SCOPES_CLAIMS)
    public String getRequestedScopeClaims() {
        return requestedScopeClaims;
    }

    public void setRequestedScopeClaims(String requestedScopeClaims) {
        this.requestedScopeClaims = requestedScopeClaims;
    }

    public AuthCodeStore withRequestedScopeClaims(String requestedScopeClaims) {
        this.requestedScopeClaims = requestedScopeClaims;
        return this;
    }

    @DynamoDbAttribute(ATTRIBUTE_TIME_TO_EXIST)
    public long getTimeToExist() {
        return timeToExist;
    }

    public void setTimeToExist(long timeToExist) {
        this.timeToExist = timeToExist;
    }

    public AuthCodeStore withTimeToExist(long timeToExist) {
        this.timeToExist = timeToExist;
        return this;
    }

    @DynamoDbAttribute(ATTRIBUTE_HAS_BEEN_USED)
    public boolean isHasBeenUsed() {
        return hasBeenUsed;
    }

    public void setHasBeenUsed(boolean hasBeenUsed) {
        this.hasBeenUsed = hasBeenUsed;
    }

    public AuthCodeStore withHasBeenUsed(boolean hasBeenUsed) {
        this.hasBeenUsed = hasBeenUsed;
        return this;
    }
}
