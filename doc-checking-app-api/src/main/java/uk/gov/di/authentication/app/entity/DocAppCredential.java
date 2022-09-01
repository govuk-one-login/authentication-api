package uk.gov.di.authentication.app.entity;

import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbAttribute;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbPartitionKey;

import java.util.List;

@DynamoDbBean
public class DocAppCredential {

    private String subjectID;
    private List<String> credential;
    private long timeToExist;

    public DocAppCredential() {}

    @DynamoDbPartitionKey
    @DynamoDbAttribute("SubjectID")
    public String getSubjectID() {
        return subjectID;
    }

    public void setSubjectID(String subjectID) {
        this.subjectID = subjectID;
    }

    public DocAppCredential withSubjectID(String subjectID) {
        this.subjectID = subjectID;
        return this;
    }

    @DynamoDbAttribute("Credential")
    public List<String> getCredential() {
        return credential;
    }

    public void setCredential(List<String> credential) {
        this.credential = credential;
    }

    public DocAppCredential withCredential(List<String> credential) {
        this.credential = credential;
        return this;
    }

    @DynamoDbAttribute("TimeToExist")
    public long getTimeToExist() {
        return timeToExist;
    }

    public void setTimeToExist(long timeToExist) {
        this.timeToExist = timeToExist;
    }

    public DocAppCredential withTimeToExist(long timeToExist) {
        this.timeToExist = timeToExist;
        return this;
    }
}
