package uk.gov.di.authentication.shared.entity;

import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbAttribute;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbPartitionKey;

@DynamoDbBean
public class AuthSessionItem {

    public static final String ATTRIBUTE_SESSION_ID = "SessionId";
    public static final String ATTRIBUTE_IS_NEW_ACCOUNT = "isNewAccount";

    public enum AccountState {
        NEW,
        EXISTING,
        EXISTING_DOC_APP_JOURNEY,
        UNKNOWN
    }
    public static final String ATTRIBUTE_VERIFIED_MFA_METHOD_TYPE = "VerifiedMfaMethodType";

    private String sessionId;
    private String verifiedMfaMethodType;
    private long timeToLive;
    private AccountState isNewAccount;

    public AuthSessionItem() {}

    @DynamoDbPartitionKey
    @DynamoDbAttribute(ATTRIBUTE_SESSION_ID)
    public String getSessionId() {
        return sessionId;
    }

    public void setSessionId(String sessionId) {
        this.sessionId = sessionId;
    }

    public AuthSessionItem withSessionId(String sessionId) {
        this.sessionId = sessionId;
        return this;
    }

    @DynamoDbAttribute(ATTRIBUTE_VERIFIED_MFA_METHOD_TYPE)
    public String getVerifiedMfaMethodType() {
        return verifiedMfaMethodType;
    }

    public void setVerifiedMfaMethodType(String verifiedMfaMethodType) {
        this.verifiedMfaMethodType = verifiedMfaMethodType;
    }

    public AuthSessionItem withVerifiedMfaMethodType(String verifiedMfaMethodType) {
        this.verifiedMfaMethodType = verifiedMfaMethodType;
        return this;
    }

    @DynamoDbAttribute("ttl")
    public long getTimeToLive() {
        return timeToLive;
    }

    public void setTimeToLive(long timeToLive) {
        this.timeToLive = timeToLive;
    }

    public AuthSessionItem withTimeToLive(long timeToLive) {
        this.timeToLive = timeToLive;
        return this;
    }

    @DynamoDbAttribute(ATTRIBUTE_IS_NEW_ACCOUNT)
    public AccountState getIsNewAccount() {
        return this.isNewAccount;
    }

    public void setIsNewAccount(AccountState accountState) {
        this.isNewAccount = accountState;
    }

    public AuthSessionItem withAccountState(AccountState accountState) {
        this.isNewAccount = accountState;
        return this;
    }
}
