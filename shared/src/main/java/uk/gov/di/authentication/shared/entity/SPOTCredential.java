package uk.gov.di.authentication.shared.entity;

import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBAttribute;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBHashKey;

public class SPOTCredential {

    private String subjectID;
    private String serializedCredential;
    private long timeToExist;

    public SPOTCredential() {}

    @DynamoDBHashKey(attributeName = "SubjectID")
    public String getSubjectID() {
        return subjectID;
    }

    public SPOTCredential setSubjectID(String subjectID) {
        this.subjectID = subjectID;
        return this;
    }

    @DynamoDBAttribute(attributeName = "SerializedCredential")
    public String getSerializedCredential() {
        return serializedCredential;
    }

    public SPOTCredential setSerializedCredential(String serializedCredential) {
        this.serializedCredential = serializedCredential;
        return this;
    }

    @DynamoDBAttribute(attributeName = "TimeToExist")
    public long getTimeToExist() {
        return timeToExist;
    }

    public SPOTCredential setTimeToExist(long timeToExist) {
        this.timeToExist = timeToExist;
        return this;
    }
}
