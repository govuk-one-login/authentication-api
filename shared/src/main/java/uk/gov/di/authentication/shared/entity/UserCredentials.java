package uk.gov.di.authentication.shared.entity;

import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBAttribute;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBHashKey;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBIndexHashKey;
import com.amazonaws.services.dynamodbv2.model.AttributeValue;
import uk.gov.di.authentication.shared.dynamodb.DynamoDBItem;

import java.util.HashMap;
import java.util.Map;

public class UserCredentials implements DynamoDBItem {

    public static final String EMAIL = "Email";
    public static final String SUBJECT_ID = "SubjectID";
    public static final String PASSWORD = "Password";
    public static final String CREATED = "Created";
    public static final String UPDATED = "Updated";
    public static final String MIGRATED_PASSWORD = "MigratedPassword";

    private String email;
    private String subjectID;
    private String password;
    private String created;
    private String updated;
    private String migratedPassword;

    public UserCredentials() {}

    @DynamoDBHashKey(attributeName = EMAIL)
    public String getEmail() {
        return email;
    }

    public UserCredentials setEmail(String email) {
        this.email = email;
        return this;
    }

    @DynamoDBIndexHashKey(globalSecondaryIndexName = "SubjectIDIndex", attributeName = SUBJECT_ID)
    public String getSubjectID() {
        return subjectID;
    }

    public UserCredentials setSubjectID(String subjectID) {
        this.subjectID = subjectID;
        return this;
    }

    @DynamoDBAttribute(attributeName = PASSWORD)
    public String getPassword() {
        return password;
    }

    public UserCredentials setPassword(String password) {
        this.password = password;
        return this;
    }

    @DynamoDBAttribute(attributeName = CREATED)
    public String getCreated() {
        return created;
    }

    public UserCredentials setCreated(String created) {
        this.created = created;
        return this;
    }

    @DynamoDBAttribute(attributeName = UPDATED)
    public String getUpdated() {
        return updated;
    }

    public UserCredentials setUpdated(String updated) {
        this.updated = updated;
        return this;
    }

    @DynamoDBAttribute(attributeName = MIGRATED_PASSWORD)
    public String getMigratedPassword() {
        return migratedPassword;
    }

    public UserCredentials setMigratedPassword(String migratedPassword) {
        this.migratedPassword = migratedPassword;
        return this;
    }

    @Override
    public Map<String, AttributeValue> toItem() {
        Map<String, AttributeValue> attributes = new HashMap<>();
        if (getEmail() != null) attributes.put(EMAIL, new AttributeValue(getEmail()));
        if (getSubjectID() != null) attributes.put(SUBJECT_ID, new AttributeValue(getSubjectID()));
        if (getPassword() != null) attributes.put(PASSWORD, new AttributeValue(getPassword()));
        if (getCreated() != null) attributes.put(CREATED, new AttributeValue(getCreated()));
        if (getUpdated() != null) attributes.put(UPDATED, new AttributeValue(getUpdated()));
        if (getMigratedPassword() != null)
            attributes.put(MIGRATED_PASSWORD, new AttributeValue(getMigratedPassword()));
        return attributes;
    }
}
