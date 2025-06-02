package uk.gov.di.authentication.shared.entity;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbAttribute;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbConvertedBy;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbPartitionKey;
import uk.gov.di.authentication.shared.converters.CodeRequestCountMapConverter;
import uk.gov.di.authentication.shared.converters.PreservedReauthCountsForAuditMapConverter;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;

import java.util.HashMap;
import java.util.Map;

@DynamoDbBean
public class AuthSessionItem {

    private static final Logger LOG = LogManager.getLogger(AuthSessionItem.class);

    public static final String ATTRIBUTE_SESSION_ID = "SessionId";
    public static final String ATTRIBUTE_IS_NEW_ACCOUNT = "isNewAccount";
    public static final String ATTRIBUTE_RESET_PASSWORD_STATE = "resetPasswordState";
    public static final String ATTRIBUTE_RESET_MFA_STATE = "resetMfaState";
    public static final String ATTRIBUTE_VERIFIED_MFA_METHOD_TYPE = "VerifiedMfaMethodType";
    public static final String ATTRIBUTE_INTERNAL_COMMON_SUBJECT_ID = "InternalCommonSubjectId";
    public static final String ATTRIBUTE_UPLIFT_REQUIRED = "UpliftRequired";
    public static final String ATTRIBUTE_EMAIL = "Email";
    public static final String ATTRIBUTE_PASSWORD_RESET_COUNT = "PasswordResetCount";
    public static final String ATTRIBUTE_TTL = "ttl";
    public static final String ATTRIBUTE_CODE_REQUEST_COUNT_MAP = "CodeRequestCountMap";
    public static final String ATTRIBUTE_PRESERVED_REAUTH_COUNTS_FOR_AUDIT_MAP =
            "PreservedReauthCountsForAuditMap";
    public static final String ATTRIBUTE_ACHIEVED_CREDENTIAL_STRENGTH =
            "AchievedCredentialStrength";
    public static final String ATTRIBUTE_REQUESTED_CREDENTIAL_STRENGTH =
            "RequestedCredentialStrength";
    public static final String ATTRIBUTE_REQUESTED_LEVEL_OF_CONFIDENCE =
            "RequestedLevelOfConfidence";
    public static final String ATTRIBUTE_CLIENT_ID = "ClientId";
    public static final String ATTRIBUTE_CLIENT_NAME = "ClientName";
    public static final String ATTRIBUTE_IS_SMOKE_TEST = "IsSmokeTest";

    public enum AccountState {
        NEW,
        EXISTING,
        EXISTING_DOC_APP_JOURNEY,
        UNKNOWN
    }

    public enum ResetPasswordState {
        NONE,
        ATTEMPTED,
        SUCCEEDED,
    }

    public enum ResetMfaState {
        NONE,
        ATTEMPTED,
        SUCCEEDED,
    }

    private String sessionId;
    private MFAMethodType verifiedMfaMethodType;
    private long timeToLive;
    private AccountState isNewAccount;
    private ResetPasswordState resetPasswordState = ResetPasswordState.NONE;
    private ResetMfaState resetMfaState = ResetMfaState.NONE;
    private CredentialTrustLevel currentCredentialStrength;
    private String internalCommonSubjectId;
    private boolean upliftRequired;
    private String emailAddress;
    private Map<CodeRequestType, Integer> codeRequestCountMap;
    private int passwordResetCount;
    private Map<CountType, Integer> preservedReauthCountsForAuditMap;
    private CredentialTrustLevel achievedCredentialStrength;
    private CredentialTrustLevel requestedCredentialStrength;
    private LevelOfConfidence requestedLevelOfConfidence;
    private String clientId;
    private String clientName;
    private boolean isSmokeTest;

    public AuthSessionItem() {
        this.codeRequestCountMap = new HashMap<>();
        initializeCodeRequestMap();
    }

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
    public MFAMethodType getVerifiedMfaMethodType() {
        return verifiedMfaMethodType;
    }

    public void setVerifiedMfaMethodType(MFAMethodType verifiedMfaMethodType) {
        this.verifiedMfaMethodType = verifiedMfaMethodType;
    }

    public AuthSessionItem withVerifiedMfaMethodType(MFAMethodType verifiedMfaMethodType) {
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

    @DynamoDbAttribute(ATTRIBUTE_TTL)
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

    @DynamoDbAttribute(ATTRIBUTE_RESET_PASSWORD_STATE)
    public ResetPasswordState getResetPasswordState() {
        return this.resetPasswordState;
    }

    public void setResetPasswordState(ResetPasswordState resetPasswordState) {
        this.resetPasswordState = resetPasswordState;
    }

    public AuthSessionItem withResetPasswordState(ResetPasswordState resetPasswordState) {
        this.resetPasswordState = resetPasswordState;
        return this;
    }

    @DynamoDbAttribute(ATTRIBUTE_RESET_MFA_STATE)
    public ResetMfaState getResetMfaState() {
        return this.resetMfaState;
    }

    public void setResetMfaState(ResetMfaState resetMfaState) {
        this.resetMfaState = resetMfaState;
    }

    public AuthSessionItem withResetMfaState(ResetMfaState resetMfaState) {
        this.resetMfaState = resetMfaState;
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

    public boolean validateSession(String emailAddress) {
        return this.emailAddress.equals(emailAddress);
    }

    @DynamoDbAttribute(ATTRIBUTE_PASSWORD_RESET_COUNT)
    public int getPasswordResetCount() {
        return passwordResetCount;
    }

    public void setPasswordResetCount(int passwordResetCount) {
        this.passwordResetCount = passwordResetCount;
    }

    public AuthSessionItem incrementPasswordResetCount() {
        this.passwordResetCount = passwordResetCount + 1;
        return this;
    }

    public AuthSessionItem resetPasswordResetCount() {
        this.passwordResetCount = 0;
        return this;
    }

    /**
     * These getters and setters are required as a minimum for this to be a compliant DynamoDB Bean
     * class
     */
    @DynamoDbAttribute(ATTRIBUTE_CODE_REQUEST_COUNT_MAP)
    @DynamoDbConvertedBy(CodeRequestCountMapConverter.class)
    public Map<CodeRequestType, Integer> getCodeRequestCountMap() {
        return this.codeRequestCountMap;
    }

    public void setCodeRequestCountMap(Map<CodeRequestType, Integer> codeRequestCountMap) {
        this.codeRequestCountMap = codeRequestCountMap;
    }

    public int getCodeRequestCount(NotificationType notificationType, JourneyType journeyType) {
        CodeRequestType requestType =
                CodeRequestType.getCodeRequestType(notificationType, journeyType);
        return getCodeRequestCount(requestType);
    }

    public int getCodeRequestCount(CodeRequestType requestType) {
        if (requestType == null) {
            throw new IllegalArgumentException("CodeRequestType cannot be null");
        }
        LOG.info("CodeRequest count map: {}", codeRequestCountMap);
        return codeRequestCountMap.getOrDefault(requestType, 0);
    }

    public AuthSessionItem incrementCodeRequestCount(
            NotificationType notificationType, JourneyType journeyType) {
        CodeRequestType requestType =
                CodeRequestType.getCodeRequestType(notificationType, journeyType);
        int currentCount = getCodeRequestCount(requestType);
        LOG.info("CodeRequest count: {} is: {}", requestType, currentCount);
        codeRequestCountMap.put(requestType, currentCount + 1);
        LOG.info("CodeRequest count: {} incremented to: {}", requestType, currentCount + 1);
        return this;
    }

    public AuthSessionItem resetCodeRequestCount(
            NotificationType notificationType, JourneyType journeyType) {
        CodeRequestType requestType =
                CodeRequestType.getCodeRequestType(notificationType, journeyType);
        codeRequestCountMap.put(requestType, 0);
        LOG.info("CodeRequest count reset: {}", codeRequestCountMap);
        return this;
    }

    private void initializeCodeRequestMap() {
        for (CodeRequestType requestType : CodeRequestType.values()) {
            codeRequestCountMap.put(requestType, 0);
        }
    }

    @DynamoDbAttribute(ATTRIBUTE_PRESERVED_REAUTH_COUNTS_FOR_AUDIT_MAP)
    @DynamoDbConvertedBy(PreservedReauthCountsForAuditMapConverter.class)
    public Map<CountType, Integer> getPreservedReauthCountsForAuditMap() {
        return this.preservedReauthCountsForAuditMap;
    }

    public void setPreservedReauthCountsForAuditMap(
            Map<CountType, Integer> preservedReauthCountsForAuditMap) {
        this.preservedReauthCountsForAuditMap = preservedReauthCountsForAuditMap;
    }

    public AuthSessionItem withPreservedReauthCountsForAuditMap(
            Map<CountType, Integer> preservedReauthCountsForAuditMap) {
        this.preservedReauthCountsForAuditMap = preservedReauthCountsForAuditMap;
        return this;
    }

    /**
     * Returns the {@link uk.gov.di.authentication.shared.entity.CredentialTrustLevel} the user has
     * achieved in this session. This will be null initially and is set at the end of a user's
     * journey. This value is reported back to Orchestration in the /userinfo response.
     *
     * @return {{@link uk.gov.di.authentication.shared.entity.CredentialTrustLevel}: the level of
     *     credential trust a user has achieved.
     */
    @DynamoDbAttribute(ATTRIBUTE_ACHIEVED_CREDENTIAL_STRENGTH)
    public CredentialTrustLevel getAchievedCredentialStrength() {
        return this.achievedCredentialStrength;
    }

    /**
     * Sets the {@link uk.gov.di.authentication.shared.entity.CredentialTrustLevel} the user has
     * achieved in this session. Modifies the session object in place. This should only be called
     * towards the end of a user's journey once we're sure they've presented valid credentials to
     * achieve the level we're about to set. Usages of this should be careful not to downshift a
     * user's Credential Trust level.
     *
     * @param credentialStrength - the level of Credential Trust a user has achieved
     */
    public void setAchievedCredentialStrength(CredentialTrustLevel credentialStrength) {
        this.achievedCredentialStrength = credentialStrength;
    }

    /**
     * Builder like method which both sets the level of Credential Trust the user has achieved in
     * this session and returns the modified session object, enabling method chaining. This should
     * only be called towards the end of a user's journey once we're sure they've presented valid
     * credentials to achieve the level we're about to set. Usages of this should be careful not to
     * downshift a user's Credential Trust level.
     *
     * @param credentialStrength - the level of Credential Trust a user has achieved
     * @return {@link uk.gov.di.authentication.shared.entity.AuthSessionItem} - the now modified
     *     session object.
     */
    public AuthSessionItem withAchievedCredentialStrength(CredentialTrustLevel credentialStrength) {
        this.achievedCredentialStrength = credentialStrength;
        return this;
    }

    @DynamoDbAttribute(ATTRIBUTE_REQUESTED_CREDENTIAL_STRENGTH)
    public CredentialTrustLevel getRequestedCredentialStrength() {
        return requestedCredentialStrength;
    }

    public void setRequestedCredentialStrength(CredentialTrustLevel requestedCredentialStrength) {
        this.requestedCredentialStrength = requestedCredentialStrength;
    }

    public AuthSessionItem withRequestedCredentialStrength(
            CredentialTrustLevel requestedCredentialStrength) {
        this.requestedCredentialStrength = requestedCredentialStrength;
        return this;
    }

    @DynamoDbAttribute(ATTRIBUTE_REQUESTED_LEVEL_OF_CONFIDENCE)
    public LevelOfConfidence getRequestedLevelOfConfidence() {
        return requestedLevelOfConfidence;
    }

    public void setRequestedLevelOfConfidence(LevelOfConfidence requestedLevelOfConfidence) {
        this.requestedLevelOfConfidence = requestedLevelOfConfidence;
    }

    public AuthSessionItem withRequestedLevelOfConfidence(
            LevelOfConfidence requestedLevelOfConfidence) {
        this.requestedLevelOfConfidence = requestedLevelOfConfidence;
        return this;
    }

    @DynamoDbAttribute(ATTRIBUTE_CLIENT_ID)
    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public AuthSessionItem withClientId(String clientId) {
        this.clientId = clientId;
        return this;
    }

    @DynamoDbAttribute(ATTRIBUTE_CLIENT_NAME)
    public String getClientName() {
        return clientName;
    }

    public void setClientName(String clientName) {
        this.clientName = clientName;
    }

    public AuthSessionItem withClientName(String clientName) {
        this.clientName = clientName;
        return this;
    }

    @DynamoDbAttribute(ATTRIBUTE_IS_SMOKE_TEST)
    public boolean getIsSmokeTest() {
        return isSmokeTest;
    }

    public void setIsSmokeTest(boolean isSmokeTest) {
        this.isSmokeTest = isSmokeTest;
    }

    public AuthSessionItem withIsSmokeTest(boolean isSmokeTest) {
        this.isSmokeTest = isSmokeTest;
        return this;
    }

    /**
     * Return a string representation of the instance that is safe to record in logs (e.g. does not
     * contain PII)
     */
    public String toLogSafeString() {
        return "AuthSessionItem{sessionId = '"
                + sessionId
                + "', verifiedMfaMethodType = '"
                + verifiedMfaMethodType
                + "', timeToLive = '"
                + timeToLive
                + "', isNewAccount = '"
                + isNewAccount
                + "', resetPasswordState = '"
                + resetPasswordState
                + "', resetMfaState = '"
                + resetMfaState
                + "', internalCommonSubjectId = '"
                + internalCommonSubjectId
                + "', upliftRequired = '"
                + upliftRequired
                + "'}}";
    }
}
