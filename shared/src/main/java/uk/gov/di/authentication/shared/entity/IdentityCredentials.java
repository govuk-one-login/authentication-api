package uk.gov.di.authentication.shared.entity;

import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBAttribute;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBHashKey;

import java.util.Map;

public class IdentityCredentials {

    private String subjectID;
    private String coreIdentityJWT;
    private long timeToExist;
    private Map<String, String> additionalClaims;
    private String ipvVot;
    private String ipvCoreIdentity;

    public IdentityCredentials() {}

    @DynamoDBHashKey(attributeName = "SubjectID")
    public String getSubjectID() {
        return subjectID;
    }

    public IdentityCredentials setSubjectID(String subjectID) {
        this.subjectID = subjectID;
        return this;
    }

    @DynamoDBAttribute(attributeName = "CoreIdentityJWT")
    public String getCoreIdentityJWT() {
        return coreIdentityJWT;
    }

    public IdentityCredentials setCoreIdentityJWT(String coreIdentityJWT) {
        this.coreIdentityJWT = coreIdentityJWT;
        return this;
    }

    @DynamoDBAttribute(attributeName = "TimeToExist")
    public long getTimeToExist() {
        return timeToExist;
    }

    public IdentityCredentials setTimeToExist(long timeToExist) {
        this.timeToExist = timeToExist;
        return this;
    }

    @DynamoDBAttribute(attributeName = "AdditionalClaims")
    public Map<String, String> getAdditionalClaims() {
        return additionalClaims;
    }

    public IdentityCredentials setAdditionalClaims(Map<String, String> additionalClaims) {
        this.additionalClaims = additionalClaims;
        return this;
    }

    @DynamoDBAttribute(attributeName = "IpvVot")
    public String getIpvVot() {
        return ipvVot;
    }

    public IdentityCredentials setIpvVot(String ipvVot) {
        this.ipvVot = ipvVot;
        return this;
    }

    @DynamoDBAttribute(attributeName = "IpvCoreIdentity")
    public String getIpvCoreIdentity() {
        return ipvCoreIdentity;
    }

    public IdentityCredentials setIpvCoreIdentity(String ipvCoreIdentity) {
        this.ipvCoreIdentity = ipvCoreIdentity;
        return this;
    }
}
