package uk.gov.di.authentication.shared.entity;

import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBAttribute;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBHashKey;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBIndexHashKey;

public class UserCredentials {

    private String email;
    private String subjectID;
    private String password;
    private String created;
    private String updated;

    public UserCredentials() {}

    @DynamoDBHashKey(attributeName = "Email")
    public String getEmail() {
        return email;
    }

    public UserCredentials setEmail(String email) {
        this.email = email;
        return this;
    }

    @DynamoDBIndexHashKey(globalSecondaryIndexName = "SubjectIDIndex", attributeName = "SubjectID")
    public String getSubjectID() {
        return subjectID;
    }

    public UserCredentials setSubjectID(String subjectID) {
        this.subjectID = subjectID;
        return this;
    }

    @DynamoDBAttribute(attributeName = "Password")
    public String getPassword() {
        return password;
    }

    public UserCredentials setPassword(String password) {
        this.password = password;
        return this;
    }

    @DynamoDBAttribute(attributeName = "Created")
    public String getCreated() {
        return created;
    }

    public UserCredentials setCreated(String created) {
        this.created = created;
        return this;
    }

    @DynamoDBAttribute(attributeName = "Updated")
    public String getUpdated() {
        return updated;
    }

    public UserCredentials setUpdated(String updated) {
        this.updated = updated;
        return this;
    }
}
