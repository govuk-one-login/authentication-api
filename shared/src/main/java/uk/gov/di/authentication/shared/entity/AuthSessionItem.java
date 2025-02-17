package uk.gov.di.authentication.shared.entity;

import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbAttribute;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbPartitionKey;

@DynamoDbBean
public class AuthSessionItem {

    public static final String ATTRIBUTE_SESSION_ID = "SessionId";
    public static final String ATTRIBUTE_IS_NEW_ACCOUNT = "isNewAccount";
    public static final String ATTRIBUTE_CURRENT_CREDENTIAL_STRENGTH = "currentCredentialStrength";
    public static final String ATTRIBUTE_VERIFIED_MFA_METHOD_TYPE = "VerifiedMfaMethodType";
    public static final String ATTRIBUTE_INTERNAL_COMMON_SUBJECT_ID = "InternalCommonSubjectId";
    public static final String ATTRIBUTE_UPLIFT_REQUIRED = "UpliftRequired";
    public static final String ATTRIBUTE_EMAIL = "Email";

    public enum AccountState {
        NEW,
        EXISTING,
        EXISTING_DOC_APP_JOURNEY,
        UNKNOWN
    }

    private String sessionId;
    private String verifiedMfaMethodType;
    private long timeToLive;
    private AccountState isNewAccount;
    private CredentialTrustLevel currentCredentialStrength;
    private String internalCommonSubjectId;
    private boolean upliftRequired;
    private String emailAddress;

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

    @DynamoDbAttribute(ATTRIBUTE_INTERNAL_COMMON_SUBJECT_ID)
    public String getInternalCommonSubjectId() {
        return internalCommonSubjectId;
    }

    public void setInternalCommonSubjectId(String internalCommonSubjectId) {
        this.internalCommonSubjectId = internalCommonSubjectId;
    }

    public AuthSessionItem withInternalCommonSubjectId(String internalCommonSubjectId) {
        this.internalCommonSubjectId = internalCommonSubjectId;
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

    @DynamoDbAttribute(ATTRIBUTE_CURRENT_CREDENTIAL_STRENGTH)
    public CredentialTrustLevel getCurrentCredentialStrength() {
        return this.currentCredentialStrength;
    }

    public void setCurrentCredentialStrength(CredentialTrustLevel currentCredentialStrength) {
        this.currentCredentialStrength = currentCredentialStrength;
    }

    public AuthSessionItem withCurrentCredentialStrength(
            CredentialTrustLevel currentCredentialStrength) {
        this.currentCredentialStrength = currentCredentialStrength;
        return this;
    }

    @DynamoDbAttribute(ATTRIBUTE_UPLIFT_REQUIRED)
    public boolean getUpliftRequired() {
        return this.upliftRequired;
    }

    public void setUpliftRequired(boolean upliftRequired) {
        this.upliftRequired = upliftRequired;
    }

    public AuthSessionItem withUpliftRequired(boolean upliftRequired) {
        this.upliftRequired = upliftRequired;
        return this;
    }

    @DynamoDbAttribute(ATTRIBUTE_EMAIL)
    public String getEmailAddress() {
        return emailAddress;
    }

    public void setEmailAddress(String emailAddress) {
        this.emailAddress = emailAddress;
    }

    public AuthSessionItem withEmailAddress(String emailAddress) {
        this.emailAddress = emailAddress;
        return this;
    }
}
