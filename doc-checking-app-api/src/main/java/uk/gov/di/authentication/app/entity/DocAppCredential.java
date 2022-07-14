package uk.gov.di.authentication.app.entity;

import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBAttribute;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBHashKey;

import java.util.List;

public class DocAppCredential {

    private String subjectID;
    private List<String> credential;
    private long timeToExist;

    public DocAppCredential() {}

    @DynamoDBHashKey(attributeName = "SubjectID")
    public String getSubjectID() {
        return subjectID;
    }

    public DocAppCredential setSubjectID(String subjectID) {
        this.subjectID = subjectID;
        return this;
    }

    @DynamoDBAttribute(attributeName = "Credential")
    public List<String> getCredential() {
        return credential;
    }

    public DocAppCredential setCredential(List<String> credential) {
        this.credential = credential;
        return this;
    }

    @DynamoDBAttribute(attributeName = "TimeToExist")
    public long getTimeToExist() {
        return timeToExist;
    }

    public DocAppCredential setTimeToExist(long timeToExist) {
        this.timeToExist = timeToExist;
        return this;
    }
}
