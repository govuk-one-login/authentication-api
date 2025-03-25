package uk.gov.di.authentication.shared.entity;

import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbAttribute;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbPartitionKey;

import java.util.List;

@DynamoDbBean
public class AuthCodeStore {

    private static final String ATTRIBUTE_SUBJECT_ID = "SubjectID";
    private static final String ATTRIBUTE_AUTH_CODE = "AuthCode";
    private static final String ATTRIBUTE_CLAIMS = "Claims";
    private static final String ATTRIBUTE_TIME_TO_EXIST = "TimeToExist";
    private static final String ATTRIBUTE_HAS_BEEN_USED = "HasBeenUsed";
    private static final String ATTRIBUTE_SECTOR_IDENTIFIER = "SectorIdentifier";
    private static final String ATTRIBUTE_IS_NEW_ACCOUNT = "IsNewAccount";
    private static final String ATTRIBUTE_PASSWORD_RESET_TIME = "PasswordResetTime";
    private static final String JOURNEY_ID = "JourneyID";

    private String subjectID;
    private String authCode;
    private List<String> claims;
    private long timeToExist;
    private boolean hasBeenUsed;
    private String sectorIdentifier;
    private boolean isNewAccount;
    private Long passwordResetTime;
    private String journeyID;

    public AuthCodeStore() {}

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

    @DynamoDbPartitionKey
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

    @DynamoDbAttribute(ATTRIBUTE_CLAIMS)
    public List<String> getClaims() {
        return claims;
    }

    public void setClaims(List<String> claims) {
        this.claims = claims;
    }

    public AuthCodeStore withClaims(List<String> claims) {
        this.claims = claims;
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

    @DynamoDbAttribute(ATTRIBUTE_SECTOR_IDENTIFIER)
    public String getSectorIdentifier() {
        return sectorIdentifier;
    }

    public void setSectorIdentifier(String sectorIdentifier) {
        this.sectorIdentifier = sectorIdentifier;
    }

    public AuthCodeStore withSectorIdentifier(String sectorIdentifier) {
        this.sectorIdentifier = sectorIdentifier;
        return this;
    }

    @DynamoDbAttribute(ATTRIBUTE_IS_NEW_ACCOUNT)
    public boolean getIsNewAccount() {
        return isNewAccount;
    }

    public void setIsNewAccount(boolean isNewAccount) {
        this.isNewAccount = isNewAccount;
    }

    public AuthCodeStore withIsNewAccount(boolean isNewAccount) {
        this.isNewAccount = isNewAccount;
        return this;
    }

    @DynamoDbAttribute(ATTRIBUTE_PASSWORD_RESET_TIME)
    public Long getPasswordResetTime() {
        return passwordResetTime;
    }

    public void setPasswordResetTime(Long passwordResetTime) {
        this.passwordResetTime = passwordResetTime;
    }

    public AuthCodeStore withPasswordResetTime(Long passwordResetTime) {
        this.passwordResetTime = passwordResetTime;
        return this;
    }

    @DynamoDbAttribute(JOURNEY_ID)
    public String getJourneyId() {
        return journeyID;
    }

    public void setJourneyID(String journeyID) {
        this.journeyID = journeyID;
    }

    public AuthCodeStore withJourneyID(String journeyID) {
        this.journeyID = journeyID;
        return this;
    }
}
