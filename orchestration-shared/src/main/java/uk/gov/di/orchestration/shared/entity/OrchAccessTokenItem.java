package uk.gov.di.orchestration.shared.entity;

import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbAttribute;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbPartitionKey;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbSecondaryPartitionKey;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbSortKey;

@DynamoDbBean
public class OrchAccessTokenItem {

    private static final String ATTRIBUTE_CLIENT_AND_RP_PAIRWISE_ID = "ClientAndRpPairwiseId";
    private static final String ATTRIBUTE_AUTH_CODE = "AuthCode";
    private static final String ATTRIBUTE_TOKEN = "Token";
    private static final String ATTRIBUTE_INTERNAL_PAIRWISE_SUBJECT_ID =
            "InternalPairwiseSubjectId";
    private static final String ATTRIBUTE_CLIENT_SESSION_ID = "ClientSessionId";

    private String clientAndRpPairwiseId;
    private String authCode;
    private String token;
    private String internalPairwiseSubjectId;
    private String clientSessionId;

    @DynamoDbPartitionKey
    @DynamoDbAttribute(ATTRIBUTE_CLIENT_AND_RP_PAIRWISE_ID)
    public String getClientAndRpPairwiseId() {
        return clientAndRpPairwiseId;
    }

    public void setClientAndRpPairwiseId(String clientAndRpPairwiseId) {
        this.clientAndRpPairwiseId = clientAndRpPairwiseId;
    }

    public OrchAccessTokenItem withClientAndRpPairwiseId(String clientAndRpPairwiseId) {
        this.clientAndRpPairwiseId = clientAndRpPairwiseId;
        return this;
    }

    @DynamoDbSortKey
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
}
