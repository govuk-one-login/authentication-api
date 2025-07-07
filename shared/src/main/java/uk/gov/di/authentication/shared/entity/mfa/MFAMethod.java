package uk.gov.di.authentication.shared.entity.mfa;

import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbAttribute;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbConvertedBy;
import uk.gov.di.authentication.shared.dynamodb.BooleanToIntAttributeConverter;
import uk.gov.di.authentication.shared.entity.PriorityIdentifier;

import java.util.Objects;

@DynamoDbBean
public class MFAMethod implements Comparable<MFAMethod> {

    public static final String ATTRIBUTE_MFA_METHOD_TYPE = "MfaMethodType";
    public static final String ATTRIBUTE_CREDENTIAL_VALUE = "CredentialValue";
    public static final String ATTRIBUTE_ENABLED = "Enabled";
    public static final String ATTRIBUTE_METHOD_VERIFIED = "MethodVerified";
    public static final String ATTRIBUTE_UPDATED = "Updated";
    public static final String ATTRIBUTE_DESTINATION = "Destination";
    public static final String ATTRIBUTE_PRIORITY = "PriorityIdentifier";
    public static final String ATTRIBUTE_MFA_IDENTIFIER = "MFAIdentifier";

    private String mfaMethodType;
    private String credentialValue;
    private boolean methodVerified;
    private boolean enabled;
    private String updated;
    private String destination;
    private String priority;
    private String mfaIdentifier;

    public MFAMethod() {}

    public MFAMethod(
            String mfaMethodType,
            String credentialValue,
            boolean methodVerified,
            boolean enabled,
            String updated) {
        this.mfaMethodType = mfaMethodType;
        this.credentialValue = credentialValue;
        this.methodVerified = methodVerified;
        this.enabled = enabled;
        this.updated = updated;
    }

    public MFAMethod(MFAMethod source) {
        if (source == null) throw new IllegalArgumentException("MFAMethod is required to copy");
        this.mfaMethodType = source.getMfaMethodType();
        this.credentialValue = source.getCredentialValue();
        this.methodVerified = source.methodVerified;
        this.enabled = source.enabled;
        this.updated = source.getUpdated();
        this.destination = source.getDestination();
        this.priority = source.getPriority();
        this.mfaIdentifier = source.getMfaIdentifier();
    }

    public static MFAMethod authAppMfaMethod(
            String credentialValue,
            boolean methodVerified,
            boolean enabled,
            PriorityIdentifier priority,
            String mfaIdentifier) {
        return new MFAMethod()
                .withMfaMethodType(MFAMethodType.AUTH_APP.getValue())
                .withCredentialValue(credentialValue)
                .withMethodVerified(methodVerified)
                .withEnabled(enabled)
                .withPriority(priority.name())
                .withMfaIdentifier(mfaIdentifier);
    }

    public static MFAMethod smsMfaMethod(
            boolean methodVerified,
            boolean enabled,
            String destination,
            PriorityIdentifier priority,
            String mfaIdentifier) {
        return new MFAMethod()
                .withMfaMethodType(MFAMethodType.SMS.getValue())
                .withMethodVerified(methodVerified)
                .withEnabled(enabled)
                .withDestination(destination)
                .withPriority(priority.name())
                .withMfaIdentifier(mfaIdentifier);
    }

    @DynamoDbAttribute(ATTRIBUTE_MFA_METHOD_TYPE)
    public String getMfaMethodType() {
        return mfaMethodType;
    }

    public void setMfaMethodType(String mfaMethodType) {
        this.mfaMethodType = mfaMethodType;
    }

    public MFAMethod withMfaMethodType(String mfaMethodType) {
        this.mfaMethodType = mfaMethodType;
        return this;
    }

    @DynamoDbAttribute(ATTRIBUTE_CREDENTIAL_VALUE)
    public String getCredentialValue() {
        return credentialValue;
    }

    public void setCredentialValue(String credentialValue) {
        this.credentialValue = credentialValue;
    }

    public MFAMethod withCredentialValue(String credentialValue) {
        this.credentialValue = credentialValue;
        return this;
    }

    @DynamoDbAttribute(ATTRIBUTE_DESTINATION)
    public String getDestination() {
        return destination;
    }

    public void setDestination(String destination) {
        this.destination = destination;
    }

    public MFAMethod withDestination(String destination) {
        this.destination = destination;
        return this;
    }

    @DynamoDbAttribute(ATTRIBUTE_PRIORITY)
    public String getPriority() {
        return priority;
    }

    public void setPriority(String priority) {
        this.priority = priority;
    }

    public MFAMethod withPriority(String priority) {
        this.priority = priority;
        return this;
    }

    @DynamoDbConvertedBy(BooleanToIntAttributeConverter.class)
    @DynamoDbAttribute(ATTRIBUTE_METHOD_VERIFIED)
    public boolean isMethodVerified() {
        return methodVerified;
    }

    public void setMethodVerified(boolean methodVerified) {
        this.methodVerified = methodVerified;
    }

    public MFAMethod withMethodVerified(boolean methodVerified) {
        this.methodVerified = methodVerified;
        return this;
    }

    @DynamoDbConvertedBy(BooleanToIntAttributeConverter.class)
    @DynamoDbAttribute(ATTRIBUTE_ENABLED)
    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public MFAMethod withEnabled(boolean enabled) {
        this.enabled = enabled;
        return this;
    }

    @DynamoDbAttribute(ATTRIBUTE_UPDATED)
    public String getUpdated() {
        return updated;
    }

    public void setUpdated(String updated) {
        this.updated = updated;
    }

    public MFAMethod withUpdated(String updated) {
        this.updated = updated;
        return this;
    }

    @DynamoDbAttribute(ATTRIBUTE_MFA_IDENTIFIER)
    public String getMfaIdentifier() {
        return mfaIdentifier;
    }

    public void setMfaIdentifier(String mfaIdentifier) {
        this.mfaIdentifier = mfaIdentifier;
    }

    public MFAMethod withMfaIdentifier(String mfaIdentifier) {
        this.mfaIdentifier = mfaIdentifier;
        return this;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        MFAMethod that = (MFAMethod) o;
        return Objects.equals(mfaMethodType, that.mfaMethodType)
                && Objects.equals(credentialValue, that.credentialValue)
                && Objects.equals(methodVerified, that.methodVerified)
                && Objects.equals(enabled, that.enabled)
                && Objects.equals(destination, that.destination)
                && Objects.equals(priority, that.priority)
                && Objects.equals(mfaIdentifier, that.mfaIdentifier);
    }

    @Override
    public int hashCode() {
        return Objects.hash(mfaMethodType, credentialValue, methodVerified, enabled, updated);
    }

    @Override
    public int compareTo(MFAMethod other) {
        if (this.mfaIdentifier == null && other.mfaIdentifier == null) {
            return 0;
        }
        if (this.mfaIdentifier == null) {
            return -1;
        }
        if (other.mfaIdentifier == null) {
            return 1;
        }
        return this.mfaIdentifier.compareTo(other.mfaIdentifier);
    }
}
