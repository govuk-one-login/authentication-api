package uk.gov.di.authentication.shared.entity;

import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbAttribute;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbPartitionKey;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbSecondaryPartitionKey;

import java.util.List;

@DynamoDbBean
public class UserCredentials {

    public static final String ATTRIBUTE_EMAIL = "Email";
    public static final String ATTRIBUTE_SUBJECT_ID = "SubjectID";
    public static final String ATTRIBUTE_PASSWORD = "Password";
    public static final String ATTRIBUTE_CREATED = "Created";
    public static final String ATTRIBUTE_UPDATED = "Updated";
    public static final String ATTRIBUTE_MIGRATED_PASSWORD = "MigratedPassword";
    public static final String ATTRIBUTE_MFA_METHODS = "MfaMethods";
    private static final String ATTRIBUTE_MFA_METHODS_V2 = "MfaMethodsV2";
    public static final String ATTRIBUTE_TEST_USER = "testUser";

    private String email;
    private String subjectID;
    private String password;
    private String created;
    private String updated;
    private String migratedPassword;
    private List<MFAMethod> mfaMethods;
    private List<MFAMethodV2> mfaMethodsV2;
    private int testUser;

    public UserCredentials() {}

    @DynamoDbPartitionKey
    @DynamoDbAttribute(ATTRIBUTE_EMAIL)
    public String getEmail() {
        return email;
    }

    public UserCredentials withEmail(String email) {
        this.email = email;
        return this;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public void setSubjectID(String subjectID) {
        this.subjectID = subjectID;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public void setCreated(String created) {
        this.created = created;
    }

    public void setUpdated(String updated) {
        this.updated = updated;
    }

    public void setMigratedPassword(String migratedPassword) {
        this.migratedPassword = migratedPassword;
    }

    public void setMfaMethods(List<MFAMethod> mfaMethods) {
        this.mfaMethods = mfaMethods;
    }

    @DynamoDbSecondaryPartitionKey(indexNames = {"SubjectIDIndex"})
    @DynamoDbAttribute(ATTRIBUTE_SUBJECT_ID)
    public String getSubjectID() {
        return subjectID;
    }

    public UserCredentials withSubjectID(String subjectID) {
        this.subjectID = subjectID;
        return this;
    }

    @DynamoDbAttribute(ATTRIBUTE_PASSWORD)
    public String getPassword() {
        return password;
    }

    public UserCredentials withPassword(String password) {
        this.password = password;
        return this;
    }

    @DynamoDbAttribute(ATTRIBUTE_CREATED)
    public String getCreated() {
        return created;
    }

    public UserCredentials withCreated(String created) {
        this.created = created;
        return this;
    }

    @DynamoDbAttribute(ATTRIBUTE_UPDATED)
    public String getUpdated() {
        return updated;
    }

    public UserCredentials withUpdated(String updated) {
        this.updated = updated;
        return this;
    }

    @DynamoDbAttribute(ATTRIBUTE_MIGRATED_PASSWORD)
    public String getMigratedPassword() {
        return migratedPassword;
    }

    public UserCredentials withMigratedPassword(String migratedPassword) {
        this.migratedPassword = migratedPassword;
        return this;
    }

    @DynamoDbAttribute(ATTRIBUTE_MFA_METHODS)
    public List<MFAMethod> getMfaMethods() {
        return mfaMethods;
    }

    public UserCredentials withMfaMethods(List<MFAMethod> mfaMethods) {
        this.mfaMethods = mfaMethods;
        return this;
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

    @DynamoDbAttribute(ATTRIBUTE_MFA_METHODS_V2)
    public List<MFAMethodV2> getMfaMethodsV2() {
        return mfaMethodsV2;
    }

    public UserCredentials withMfaMethodsV2(List<MFAMethodV2> mfaMethodsV2) {
        this.mfaMethodsV2 = mfaMethodsV2;
        return this;
    }

    public void setMfaMethodsV2(List<MFAMethodV2> mfaMethodsV2) {
        this.mfaMethodsV2 = mfaMethodsV2;
    }

    public UserCredentials addMfaMethodV2(MFAMethodV2 mfaMethodV2) {
        if (this.mfaMethodsV2 == null) {
            this.mfaMethodsV2 = List.of(mfaMethodV2);
        } else {
            this.mfaMethodsV2.add(mfaMethodV2);
        }
        return this;
    }

    public UserCredentials deleteMfaMethodV2(int mfaIdentifier) {
        if (this.mfaMethodsV2 == null) {
            return this;
        } else {
            this.mfaMethodsV2.removeIf(t -> t.getMfaIdentifier() == (mfaIdentifier));
        }
        return this;
    }

    public UserCredentials removeAuthAppByCredentialIfPresent(String authAppCredential) {
        if (this.mfaMethods == null) {
            return this;
        } else {
            this.mfaMethods.removeIf(t -> t.getCredentialValue().equals(authAppCredential));
            return this;
        }
    }

    @DynamoDbAttribute(ATTRIBUTE_TEST_USER)
    @DynamoDbSecondaryPartitionKey(indexNames = {"TestUserIndex"})
    public int getTestUser() {
        return testUser;
    }

    public void setTestUser(int isTestUser) {
        this.testUser = isTestUser;
    }
}