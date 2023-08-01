package uk.gov.di.authentication.shared.entity.token;

import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbAttribute;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbPartitionKey;

import java.util.ArrayList;
import java.util.List;

@DynamoDbBean
public class AccessTokenStore {

    private String accessToken;
    private String subjectID;
    private List<String> scopes = new ArrayList<>();
    private long timeToExist;
    private boolean used;

    @DynamoDbPartitionKey
    @DynamoDbAttribute("AccessToken")
    public String getAccessToken() {
        return accessToken;
    }

    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }

    public AccessTokenStore withAccessToken(String accessToken) {
        this.accessToken = accessToken;
        return this;
    }

    @DynamoDbAttribute("SubjectID")
    public String getSubjectID() {
        return subjectID;
    }

    public void setSubjectID(String subjectID) {
        this.subjectID = subjectID;
    }

    public AccessTokenStore withSubjectID(String subjectID) {
        this.subjectID = subjectID;
        return this;
    }

    @DynamoDbAttribute("Scopes")
    public List<String> getScopes() {
        return scopes;
    }

    public void setScopes(List<String> scopes) {
        this.scopes = scopes;
    }

    public AccessTokenStore withScopes(List<String> scopes) {
        this.scopes = scopes;
        return this;
    }

    @DynamoDbAttribute("TimeToExist")
    public long getTimeToExist() {
        return timeToExist;
    }

    public void setTimeToExist(long timeToExist) {
        this.timeToExist = timeToExist;
    }

    public AccessTokenStore withTimeToExist(long timeToExist) {
        this.timeToExist = timeToExist;
        return this;
    }

    @DynamoDbAttribute("Used")
    public boolean isUsed() {
        return used;
    }

    public void setUsed(boolean used) {
        this.used = used;
    }

    public AccessTokenStore withUsed(boolean used) {
        this.used = used;
        return this;
    }
}
