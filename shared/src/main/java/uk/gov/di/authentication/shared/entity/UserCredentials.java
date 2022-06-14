package uk.gov.di.authentication.shared.entity;

import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBAttribute;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBHashKey;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBIndexHashKey;
import com.amazonaws.services.dynamodbv2.model.AttributeValue;
import uk.gov.di.authentication.shared.dynamodb.DynamoDBItem;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class UserCredentials implements DynamoDBItem {

    public static final String ATTRIBUTE_EMAIL = "Email";
    public static final String ATTRIBUTE_SUBJECT_ID = "SubjectID";
    public static final String ATTRIBUTE_PASSWORD = "Password";
    public static final String ATTRIBUTE_CREATED = "Created";
    public static final String ATTRIBUTE_UPDATED = "Updated";
    public static final String ATTRIBUTE_MIGRATED_PASSWORD = "MigratedPassword";
    public static final String ATTRIBUTE_MFA_METHODS = "MfaMethods";

    private String email;
    private String subjectID;
    private String password;
    private String created;
    private String updated;
    private String migratedPassword;
    private List<MFAMethod> mfaMethods;

    public UserCredentials() {}

    @DynamoDBHashKey(attributeName = ATTRIBUTE_EMAIL)
    public String getEmail() {
        return email;
    }

    public UserCredentials setEmail(String email) {
        this.email = email;
        return this;
    }

    @DynamoDBIndexHashKey(
            globalSecondaryIndexName = "SubjectIDIndex",
            attributeName = ATTRIBUTE_SUBJECT_ID)
    public String getSubjectID() {
        return subjectID;
    }

    public UserCredentials setSubjectID(String subjectID) {
        this.subjectID = subjectID;
        return this;
    }

    @DynamoDBAttribute(attributeName = ATTRIBUTE_PASSWORD)
    public String getPassword() {
        return password;
    }

    public UserCredentials setPassword(String password) {
        this.password = password;
        return this;
    }

    @DynamoDBAttribute(attributeName = ATTRIBUTE_CREATED)
    public String getCreated() {
        return created;
    }

    public UserCredentials setCreated(String created) {
        this.created = created;
        return this;
    }

    @DynamoDBAttribute(attributeName = ATTRIBUTE_UPDATED)
    public String getUpdated() {
        return updated;
    }

    public UserCredentials setUpdated(String updated) {
        this.updated = updated;
        return this;
    }

    @DynamoDBAttribute(attributeName = ATTRIBUTE_MIGRATED_PASSWORD)
    public String getMigratedPassword() {
        return migratedPassword;
    }

    public UserCredentials setMigratedPassword(String migratedPassword) {
        this.migratedPassword = migratedPassword;
        return this;
    }

    @DynamoDBAttribute(attributeName = ATTRIBUTE_MFA_METHODS)
    public List<MFAMethod> getMfaMethods() {
        return mfaMethods;
    }

    public void setMfaMethods(List<MFAMethod> mfaMethods) {
        this.mfaMethods = mfaMethods;
    }

    public UserCredentials setMfaMethod(MFAMethod mfaMethod) {
        if (this.mfaMethods == null) {
            this.mfaMethods = List.of(mfaMethod);
        } else {
            this.mfaMethods.removeIf(
                    t -> t.getMfaMethodType().equals(mfaMethod.getMfaMethodType()));
            this.mfaMethods.add(mfaMethod);
        }
        return this;
    }

    @Override
    public Map<String, AttributeValue> toItem() {
        Map<String, AttributeValue> attributes = new HashMap<>();
        if (getEmail() != null) attributes.put(ATTRIBUTE_EMAIL, new AttributeValue(getEmail()));
        if (getSubjectID() != null)
            attributes.put(ATTRIBUTE_SUBJECT_ID, new AttributeValue(getSubjectID()));
        if (getPassword() != null)
            attributes.put(ATTRIBUTE_PASSWORD, new AttributeValue(getPassword()));
        if (getCreated() != null)
            attributes.put(ATTRIBUTE_CREATED, new AttributeValue(getCreated()));
        if (getUpdated() != null)
            attributes.put(ATTRIBUTE_UPDATED, new AttributeValue(getUpdated()));
        if (getMigratedPassword() != null)
            attributes.put(ATTRIBUTE_MIGRATED_PASSWORD, new AttributeValue(getMigratedPassword()));
        if (getMfaMethods() != null) {
            Collection<AttributeValue> methods = new ArrayList<>();
            getMfaMethods().forEach(m -> methods.add(m.toAttributeValue()));
            attributes.put(ATTRIBUTE_MFA_METHODS, new AttributeValue().withL(methods));
        }
        return attributes;
    }
}
