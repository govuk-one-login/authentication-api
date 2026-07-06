package uk.gov.di.accountmanagement.entity;

import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbAttribute;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbPartitionKey;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbSortKey;

@DynamoDbBean
public class AuthenticatorItemKey {

    private static final String ATTRIBUTE_PUBLIC_SUBJECT_ID = "PublicSubjectID";
    private static final String ATTRIBUTE_SORT_KEY = "SK";

    private String publicSubjectId;
    private String sortKey;

    @DynamoDbPartitionKey
    @DynamoDbAttribute(ATTRIBUTE_PUBLIC_SUBJECT_ID)
    public String getPublicSubjectId() {
        return publicSubjectId;
    }

    public void setPublicSubjectId(String publicSubjectId) {
        this.publicSubjectId = publicSubjectId;
    }

    @DynamoDbSortKey
    @DynamoDbAttribute(ATTRIBUTE_SORT_KEY)
    public String getSortKey() {
        return sortKey;
    }

    public void setSortKey(String sortKey) {
        this.sortKey = sortKey;
    }
}
