package uk.gov.di.orchestration.shared.entity;

import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbAttribute;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbPartitionKey;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbSecondaryPartitionKey;

@DynamoDbBean
public class OrchRefreshTokenItem {
    private static final String ATTRIBUTE_JWT_ID = "JwtId";
    private static final String ATTRIBUTE_INTERNAL_PAIRWISE_SUBJECT_ID =
            "InternalPairwiseSubjectId";
    private static final String ATTRIBUTE_TOKEN = "Token";
    private static final String ATTRIBUTE_AUTH_CODE = "AuthCode";
    private static final String ATTRIBUTE_IS_USED = "IsUsed";

    private String jwtId;
    private String internalPairwiseSubjectId;
    private String token;
    private String authCode;
    private boolean isUsed = false;

    @DynamoDbPartitionKey
    @DynamoDbAttribute(ATTRIBUTE_JWT_ID)
    public String getJwtId() {
        return jwtId;
    }

    public void setJwtId(String jwtId) {
        this.jwtId = jwtId;
    }

    public OrchRefreshTokenItem withJwtId(String jwtId) {
        this.jwtId = jwtId;
        return this;
    }

    @DynamoDbAttribute(ATTRIBUTE_INTERNAL_PAIRWISE_SUBJECT_ID)
    public String getInternalPairwiseSubjectId() {
        return internalPairwiseSubjectId;
    }

    public void setInternalPairwiseSubjectId(String internalPairwiseSubjectId) {
        this.internalPairwiseSubjectId = internalPairwiseSubjectId;
    }

    public OrchRefreshTokenItem withInternalPairwiseSubjectId(String internalPairwiseSubjectId) {
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

    public OrchRefreshTokenItem withToken(String token) {
        this.token = token;
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

    public OrchRefreshTokenItem withAuthCode(String authCode) {
        this.authCode = authCode;
        return this;
    }

    @DynamoDbAttribute(ATTRIBUTE_IS_USED)
    public boolean getIsUsed() {
        return isUsed;
    }

    public void setIsUsed(boolean isUsed) {
        this.isUsed = isUsed;
    }
}
