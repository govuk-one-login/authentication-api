package uk.gov.di.orchestration.shared.entity;

import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbAttribute;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbPartitionKey;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbSecondaryPartitionKey;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbSortKey;

@DynamoDbBean
public class OrchAccessTokenItem {

    private static final String ATTRIBUTE_CLIENT_ID = "ClientId";
    private static final String ATTRIBUTE_RP_PAIRWISE_ID = "RpPairwiseId";
    private static final String ATTRIBUTE_TOKEN = "Token";
    private static final String ATTRIBUTE_INTERNAL_PAIRWISE_SUBJECT_ID =
            "InternalPairwiseSubjectId";
    private static final String ATTRIBUTE_CLIENT_SESSION_ID = "ClientSessionId";
    private static final String ATTRIBUTE_AUTH_CODE = "AuthCode";

    private String clientId;
    private String rpPairwiseId;
    private String token;
    private String internalPairwiseSubjectId;
    private String clientSessionId;
    private String authCode;

    @DynamoDbPartitionKey
    @DynamoDbAttribute(ATTRIBUTE_CLIENT_ID)
    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public OrchAccessTokenItem withClientId(String clientId) {
        this.clientId = clientId;
        return this;
    }

    @DynamoDbSortKey
    @DynamoDbAttribute(ATTRIBUTE_RP_PAIRWISE_ID)
    public String getRpPairwiseId() {
        return rpPairwiseId;
    }

    public void setRpPairwiseId(String rpPairwiseId) {
        this.rpPairwiseId = rpPairwiseId;
    }

    public OrchAccessTokenItem withRpPairwiseId(String rpPairwiseId) {
        this.rpPairwiseId = rpPairwiseId;
        return this;
    }

    @DynamoDbAttribute(ATTRIBUTE_INTERNAL_PAIRWISE_SUBJECT_ID)
    public String getInternalPairwiseSubjectId() {
        return internalPairwiseSubjectId;
    }

    public void setInternalPairwiseSubjectId(String internalPairwiseSubjectId) {
        this.internalPairwiseSubjectId = internalPairwiseSubjectId;
    }

    public OrchAccessTokenItem withInternalPairwiseSubjectId(String internalPairwiseSubjectId) {
        this.internalPairwiseSubjectId = internalPairwiseSubjectId;
        return this;
    }

    @DynamoDbAttribute(ATTRIBUTE_TOKEN)
    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public OrchAccessTokenItem withToken(String token) {
        this.token = token;
        return this;
    }

    @DynamoDbAttribute(ATTRIBUTE_CLIENT_SESSION_ID)
    public String getClientSessionId() {
        return clientSessionId;
    }

    public void setClientSessionId(String clientSessionId) {
        this.clientSessionId = clientSessionId;
    }

    public OrchAccessTokenItem withClientSessionId(String clientSessionId) {
        this.clientSessionId = clientSessionId;
        return this;
    }

    @DynamoDbSecondaryPartitionKey(indexNames = "AuthCodeIndex")
    @DynamoDbAttribute(ATTRIBUTE_AUTH_CODE)
    public String getAuthCode() {
        return authCode;
    }

    public void setAuthCode(String authCode) {
        this.authCode = authCode;
    }

    public OrchAccessTokenItem withAuthCode(String authCode) {
        this.authCode = authCode;
        return this;
    }
}
