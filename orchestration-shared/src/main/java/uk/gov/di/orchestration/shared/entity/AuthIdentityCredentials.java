package uk.gov.di.orchestration.shared.entity;

import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbAttribute;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbPartitionKey;

import java.util.Map;

@DynamoDbBean
public class AuthIdentityCredentials {

    private String subjectID;
    private String coreIdentityJWT;
    private long timeToExist;
    private Map<String, String> additionalClaims;
    private String ipvVot;
    private String ipvCoreIdentity;

    public AuthIdentityCredentials() {}

    @DynamoDbPartitionKey
    @DynamoDbAttribute("SubjectID")
    public String getSubjectID() {
        return subjectID;
    }

    public void setSubjectID(String subjectID) {
        this.subjectID = subjectID;
    }

    public AuthIdentityCredentials withSubjectID(String subjectID) {
        this.subjectID = subjectID;
        return this;
    }

    @DynamoDbAttribute("CoreIdentityJWT")
    public String getCoreIdentityJWT() {
        return coreIdentityJWT;
    }

    public void setCoreIdentityJWT(String coreIdentityJWT) {
        this.coreIdentityJWT = coreIdentityJWT;
    }

    public AuthIdentityCredentials withCoreIdentityJWT(String coreIdentityJWT) {
        this.coreIdentityJWT = coreIdentityJWT;
        return this;
    }

    @DynamoDbAttribute("TimeToExist")
    public long getTimeToExist() {
        return timeToExist;
    }

    public void setTimeToExist(long timeToExist) {
        this.timeToExist = timeToExist;
    }

    public AuthIdentityCredentials withTimeToExist(long timeToExist) {
        this.timeToExist = timeToExist;
        return this;
    }

    @DynamoDbAttribute("AdditionalClaims")
    public Map<String, String> getAdditionalClaims() {
        return additionalClaims;
    }

    public void setAdditionalClaims(Map<String, String> additionalClaims) {
        this.additionalClaims = additionalClaims;
    }

    public AuthIdentityCredentials withAdditionalClaims(Map<String, String> additionalClaims) {
        this.additionalClaims = additionalClaims;
        return this;
    }

    @DynamoDbAttribute("IpvVot")
    public String getIpvVot() {
        return ipvVot;
    }

    public void setIpvVot(String ipvVot) {
        this.ipvVot = ipvVot;
    }

    public AuthIdentityCredentials withIpvVot(String ipvVot) {
        this.ipvVot = ipvVot;
        return this;
    }

    @DynamoDbAttribute("IpvCoreIdentity")
    public String getIpvCoreIdentity() {
        return ipvCoreIdentity;
    }

    public void setIpvCoreIdentity(String ipvCoreIdentity) {
        this.ipvCoreIdentity = ipvCoreIdentity;
    }

    public AuthIdentityCredentials withIpvCoreIdentity(String ipvCoreIdentity) {
        this.ipvCoreIdentity = ipvCoreIdentity;
        return this;
    }
}
