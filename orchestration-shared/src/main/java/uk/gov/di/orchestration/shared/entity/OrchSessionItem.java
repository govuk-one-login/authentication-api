package uk.gov.di.orchestration.shared.entity;

import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbAttribute;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbPartitionKey;

@DynamoDbBean
public class OrchSessionItem {

    public static final String ATTRIBUTE_SESSION_ID = "SessionId";
    public static final String ATTRIBUTE_EMAIL = "Email";
    public static final String ATTRIBUTE_VERIFIED_MFA_METHOD_TYPE = "VerifiedMfaMethodType";
    public static final String ATTRIBUTE_RP_PAIRWISE_ID = "RpPairwiseId";

    private String sessionId;
    private long timeToLive;
    private String email;
    private String verifiedMfaMethodType;
    private String rpPairwiseId;

    public OrchSessionItem() {}

    public OrchSessionItem(String sessionId) {
        this.sessionId = sessionId;
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

    @DynamoDbAttribute(ATTRIBUTE_EMAIL)
    public String getEmailAddress() {
        return email;
    }

    public void setEmailAddress(String email) {
        this.email = email;
    }

    public OrchSessionItem withEmailAddress(String email) {
        this.email = email;
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

    @DynamoDbAttribute(ATTRIBUTE_RP_PAIRWISE_ID)
    public String getRpPairwiseId() {
        return rpPairwiseId;
    }

    public void setRpPairwiseId(String rpPairwiseId) {
        this.rpPairwiseId = rpPairwiseId;
    }

    public OrchSessionItem withRpPairwiseId(String rpPairwiseId) {
        this.rpPairwiseId = rpPairwiseId;
        return this;
    }
}
