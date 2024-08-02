package uk.gov.di.authentication.shared.entity;

import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbAttribute;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbConvertedBy;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import uk.gov.di.authentication.shared.dynamodb.BooleanToIntAttributeConverter;

import java.util.Map;
import java.util.Objects;

@DynamoDbBean
public class MFAMethod {

    public static final String ATTRIBUTE_MFA_METHOD_TYPE = "MfaMethodType";
    public static final String ATTRIBUTE_CREDENTIAL_VALUE = "CredentialValue";
    public static final String ATTRIBUTE_ENABLED = "Enabled";
    public static final String ATTRIBUTE_METHOD_VERIFIED = "MethodVerified";
    public static final String ATTRIBUTE_UPDATED = "Updated";
    public static final String ATTRIBUTE_DESTINATION = "Destination";
    public static final String ATTRIBUTE_PRIORITY = "PriorityIdentifier";

    private String mfaMethodType;
    private String credentialValue;
    private boolean methodVerified;
    private boolean enabled;
    private String updated;
    private String destination;
    private String priority;

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

    public MFAMethod(
            String mfaMethodType,
            String credentialValue,
            boolean methodVerified,
            boolean enabled,
            String updated,
            PriorityIdentifier priority) {
        this.mfaMethodType = mfaMethodType;
        this.credentialValue = credentialValue;
        this.methodVerified = methodVerified;
        this.enabled = enabled;
        this.updated = updated;
        this.priority = priority.name();
    }

    public MFAMethod(
            String mfaMethodType,
            boolean methodVerified,
            boolean enabled,
            String destination,
            String updated,
            PriorityIdentifier priority) {
        this.mfaMethodType = mfaMethodType;
        this.methodVerified = methodVerified;
        this.enabled = enabled;
        this.destination = destination;
        this.updated = updated;
        this.priority = priority.name();
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

    AttributeValue toAttributeValue() {
        return AttributeValue.fromM(
                Map.ofEntries(
                        Map.entry(
                                ATTRIBUTE_MFA_METHOD_TYPE,
                                AttributeValue.fromS(getMfaMethodType())),
                        Map.entry(
                                ATTRIBUTE_CREDENTIAL_VALUE,
                                AttributeValue.fromS(getCredentialValue())),
                        Map.entry(
                                ATTRIBUTE_METHOD_VERIFIED,
                                AttributeValue.fromN(isMethodVerified() ? "1" : "0")),
                        Map.entry(ATTRIBUTE_ENABLED, AttributeValue.fromN(isEnabled() ? "1" : "0")),
                        Map.entry(ATTRIBUTE_UPDATED, AttributeValue.fromS(getUpdated()))));
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
                && Objects.equals(updated, that.updated)
                && Objects.equals(destination, that.destination)
                && Objects.equals(priority, that.priority);
    }

    @Override
    public int hashCode() {
        return Objects.hash(mfaMethodType, credentialValue, methodVerified, enabled, updated);
    }
}
