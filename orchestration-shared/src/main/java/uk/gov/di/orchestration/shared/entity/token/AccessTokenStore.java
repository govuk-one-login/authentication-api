package uk.gov.di.orchestration.shared.entity.token;

import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbAttribute;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbPartitionKey;

import java.util.ArrayList;
import java.util.List;

@DynamoDbBean
public class AccessTokenStore {

    private String accessToken;
    private String subjectID;
    private List<String> claims = new ArrayList<>();
    private long timeToExist;
    private boolean used;
    private String sectorIdentifier;
    private boolean isNewAccount;

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

    @DynamoDbAttribute("Claims")
    public List<String> getClaims() {
        return claims;
    }

    public void setClaims(List<String> claims) {
        this.claims = claims;
    }

    public AccessTokenStore withClaims(List<String> claims) {
        this.claims = claims;
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

    @DynamoDbAttribute("SectorIdentifier")
    public String getSectorIdentifier() {
        return sectorIdentifier;
    }

    public void setSectorIdentifier(String sectorIdentifier) {
        this.sectorIdentifier = sectorIdentifier;
    }

    public AccessTokenStore withSectorIdentifier(String sectorIdentifier) {
        this.sectorIdentifier = sectorIdentifier;
        return this;
    }

    @DynamoDbAttribute("NewAccount")
    public boolean getIsNewAccount() {
        return isNewAccount;
    }

    public void setIsNewAccount(boolean isNewAccount) {
        this.isNewAccount = isNewAccount;
    }

    public AccessTokenStore withNewAccount(boolean isNewAccount) {
        this.isNewAccount = isNewAccount;
        return this;
    }
}
