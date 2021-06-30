package uk.gov.di.entity;

import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBAttribute;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBHashKey;

public class UserProfile {

    private String email;
    private String subjectID;
    private boolean emailVerified;
    private String phoneNumber;
    private boolean phoneNumberVerified;
    private String created;
    private String updated;

    public UserProfile() {}

    @DynamoDBHashKey(attributeName = "Email")
    public String getEmail() {
        return email;
    }

    public UserProfile setEmail(String email) {
        this.email = email;
        return this;
    }

    @DynamoDBAttribute(attributeName = "SubjectID")
    public String getSubjectID() {
        return subjectID;
    }

    public UserProfile setSubjectID(String subjectID) {
        this.subjectID = subjectID;
        return this;
    }

    @DynamoDBAttribute(attributeName = "EmailVerified")
    public boolean isEmailVerified() {
        return emailVerified;
    }

    public UserProfile setEmailVerified(boolean emailVerified) {
        this.emailVerified = emailVerified;
        return this;
    }

    @DynamoDBAttribute(attributeName = "PhoneNumber")
    public String getPhoneNumber() {
        return phoneNumber;
    }

    public UserProfile setPhoneNumber(String phoneNumber) {
        this.phoneNumber = phoneNumber;
        return this;
    }

    @DynamoDBAttribute(attributeName = "PhoneNumberVerified")
    public boolean isPhoneNumberVerified() {
        return phoneNumberVerified;
    }

    public UserProfile setPhoneNumberVerified(boolean phoneNumberVerified) {
        this.phoneNumberVerified = phoneNumberVerified;
        return this;
    }

    @DynamoDBAttribute(attributeName = "Created")
    public String getCreated() {
        return created;
    }

    public UserProfile setCreated(String created) {
        this.created = created;
        return this;
    }

    @DynamoDBAttribute(attributeName = "Updated")
    public String getUpdated() {
        return updated;
    }

    public UserProfile setUpdated(String updated) {
        this.updated = updated;
        return this;
    }
}
