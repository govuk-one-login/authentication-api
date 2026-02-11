package uk.gov.di.authentication.accountdata.entity;

import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbAttribute;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbPartitionKey;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbSortKey;

@DynamoDbBean
public abstract class Authenticator<T extends Authenticator<T>> {

    public static final String ATTRIBUTE_PUBLIC_SUBJECT_ID = "PublicSubjectId";
    public static final String ATTRIBUTE_SORT_KEY = "SK";
    public static final String ATTRIBUTE_CREATED = "Created";
    public static final String ATTRIBUTE_LAST_USED = "LastUsed";
    public static final String ATTRIBUTE_CREDENTIAL = "Credential";
    public static final String ATTRIBUTE_CREDENTIAL_ID = "CredentialId";
    public static final String ATTRIBUTE_TYPE = "Type";

    private String publicSubjectId;
    private String sortKey;
    private String created;
    private String lastUsed;
    private String credential;
    private String credentialId;
    private String type;

    protected abstract T self();

    @DynamoDbPartitionKey
    @DynamoDbAttribute(ATTRIBUTE_PUBLIC_SUBJECT_ID)
    public String getPublicSubjectId() {
        return publicSubjectId;
    }

    public void setPublicSubjectId(String publicSubjectId) {
        this.publicSubjectId = publicSubjectId;
    }

    public T withPublicSubjectId(String publicSubjectId) {
        this.publicSubjectId = publicSubjectId;
        return self();
    }

    @DynamoDbSortKey
    @DynamoDbAttribute(ATTRIBUTE_SORT_KEY)
    public String getSortKey() {
        return sortKey != null ? sortKey : buildSortKey();
    }

    public void setSortKey(String sortKey) {
        this.sortKey = sortKey;
    }

    public T withSortKey(String sortKey) {
        this.sortKey = sortKey;
        return self();
    }

    @DynamoDbAttribute(ATTRIBUTE_CREATED)
    public String getCreated() {
        return created;
    }

    public void setCreated(String created) {
        this.created = created;
    }

    public T withCreated(String created) {
        this.created = created;
        return self();
    }

    @DynamoDbAttribute(ATTRIBUTE_LAST_USED)
    public String getLastUsed() {
        return lastUsed;
    }

    public void setLastUsed(String lastUsed) {
        this.lastUsed = lastUsed;
    }

    public T withLastUsed(String lastUsed) {
        this.lastUsed = lastUsed;
        return self();
    }

    @DynamoDbAttribute(ATTRIBUTE_CREDENTIAL)
    public String getCredential() {
        return credential;
    }

    public void setCredential(String credential) {
        this.credential = credential;
    }

    public T withCredential(String credential) {
        this.credential = credential;
        return self();
    }

    @DynamoDbAttribute(ATTRIBUTE_CREDENTIAL_ID)
    public String getCredentialId() {
        return credentialId;
    }

    public void setCredentialId(String credentialId) {
        this.credentialId = credentialId;
    }

    public T withCredentialId(String credentialId) {
        this.credentialId = credentialId;
        return self();
    }

    @DynamoDbAttribute(ATTRIBUTE_TYPE)
    public abstract String getType();

    public String buildSortKey() {
        return type + "#" + credentialId;
    }
}
