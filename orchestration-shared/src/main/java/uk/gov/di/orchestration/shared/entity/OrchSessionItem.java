package uk.gov.di.orchestration.shared.entity;

import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbAttribute;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbPartitionKey;

@DynamoDbBean
public class OrchSessionItem {

    public static final String ATTRIBUTE_SESSION_ID = "SessionId";
    public static final String ATTRIBUTE_PREVIOUS_SESSION_ID = "PreviousSessionId";
    public static final String ATTRIBUTE_VERIFIED_MFA_METHOD_TYPE = "VerifiedMfaMethodType";
    public static final String ATTRIBUTE_IS_NEW_ACCOUNT = "IsNewAccount";
    public static final String ATTRIBUTE_INTERNAL_COMMON_SUBJECT_ID = "InternalCommonSubjectId";

    public enum AccountState {
        NEW,
        EXISTING,
        EXISTING_DOC_APP_JOURNEY,
        UNKNOWN
    }

    private String sessionId;
    private String previousSessionId;
    private long timeToLive;
    private String verifiedMfaMethodType;
    private AccountState isNewAccount;
    private String internalCommonSubjectId;

    public OrchSessionItem() {}

    public OrchSessionItem(String sessionId) {
        this.sessionId = sessionId;
        this.isNewAccount = AccountState.UNKNOWN;
    }

    @DynamoDbPartitionKey
    @DynamoDbAttribute(ATTRIBUTE_SESSION_ID)
    public String getSessionId() {
        return sessionId;
    }

    public void setSessionId(String sessionId) {
        this.sessionId = sessionId;
    }

    public OrchSessionItem withSessionId(String sessionId) {
        this.sessionId = sessionId;
        return this;
    }

    @DynamoDbAttribute(ATTRIBUTE_PREVIOUS_SESSION_ID)
    public String getPreviousSessionId() {
        return previousSessionId;
    }

    public void setPreviousSessionId(String previousSessionId) {
        this.previousSessionId = previousSessionId;
    }

    public OrchSessionItem withPreviousSessionId(String previousSessionId) {
        this.previousSessionId = previousSessionId;
        return this;
    }

    @DynamoDbAttribute("ttl")
    public long getTimeToLive() {
        return timeToLive;
    }

    public void setTimeToLive(long timeToLive) {
        this.timeToLive = timeToLive;
    }

    public OrchSessionItem withTimeToLive(long timeToLive) {
        this.timeToLive = timeToLive;
        return this;
    }

    @DynamoDbAttribute(ATTRIBUTE_VERIFIED_MFA_METHOD_TYPE)
    public String getVerifiedMfaMethodType() {
        return verifiedMfaMethodType;
    }

    public void setVerifiedMfaMethodType(String verifiedMfaMethodType) {
        this.verifiedMfaMethodType = verifiedMfaMethodType;
    }

    public OrchSessionItem withVerifiedMfaMethodType(String verifiedMfaMethodType) {
        this.verifiedMfaMethodType = verifiedMfaMethodType;
        return this;
    }

    @DynamoDbAttribute(ATTRIBUTE_IS_NEW_ACCOUNT)
    public AccountState getIsNewAccount() {
        return this.isNewAccount;
    }

    public void setIsNewAccount(AccountState accountState) {
        this.isNewAccount = accountState;
    }

    public OrchSessionItem withAccountState(AccountState accountState) {
        this.isNewAccount = accountState;
        return this;
    }

    @DynamoDbAttribute(ATTRIBUTE_INTERNAL_COMMON_SUBJECT_ID)
    public String getInternalCommonSubjectId() {
        return internalCommonSubjectId;
    }

    public void setInternalCommonSubjectId(String internalCommonSubjectId) {
        this.internalCommonSubjectId = internalCommonSubjectId;
    }

    public OrchSessionItem withInternalCommonSubjectId(String internalCommonSubjectId) {
        this.internalCommonSubjectId = internalCommonSubjectId;
        return this;
    }
}
