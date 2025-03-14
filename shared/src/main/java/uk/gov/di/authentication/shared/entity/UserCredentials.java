package uk.gov.di.authentication.shared.entity;

import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbAttribute;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbPartitionKey;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbSecondaryPartitionKey;
import uk.gov.di.authentication.shared.entity.mfaMethodManagement.MFAMethod;

import java.util.List;
import java.util.Objects;

@DynamoDbBean
public class UserCredentials {

    public static final String ATTRIBUTE_EMAIL = "Email";
    public static final String ATTRIBUTE_SUBJECT_ID = "SubjectID";
    public static final String ATTRIBUTE_PASSWORD = "Password";
    public static final String ATTRIBUTE_CREATED = "Created";
    public static final String ATTRIBUTE_UPDATED = "Updated";
    public static final String ATTRIBUTE_MIGRATED_PASSWORD = "MigratedPassword";
    public static final String ATTRIBUTE_MFA_METHODS = "MfaMethods";
    public static final String ATTRIBUTE_TEST_USER = "testUser";

    private String email;
    private String subjectID;
    private String password;
    private String created;
    private String updated;
    private String migratedPassword;
    private List<MFAMethod> mfaMethods;
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

    public UserCredentials setMfaMethodBasedOnPriority(MFAMethod mfaMethod) {
        if (this.mfaMethods == null) {
            this.mfaMethods = List.of(mfaMethod);
        } else {
            this.mfaMethods.removeIf(t -> Objects.equals(t.getPriority(), mfaMethod.getPriority()));
            if (mfaMethod.getPriority().equals(PriorityIdentifier.DEFAULT.name())) {
                this.mfaMethods.removeIf(t -> Objects.isNull(t.getPriority()));
            }
            this.mfaMethods.add(mfaMethod);
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

    public UserCredentials removeMfaMethodByIdentifierIfPresent(String mfaMethodIdentifier) {
        if (this.mfaMethods == null) {
            return this;
        } else {
            this.mfaMethods.removeIf(t -> t.getMfaIdentifier().equals(mfaMethodIdentifier));
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
