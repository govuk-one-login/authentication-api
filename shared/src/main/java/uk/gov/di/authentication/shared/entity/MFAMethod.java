package uk.gov.di.authentication.shared.entity;

import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBAttribute;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBDocument;
import com.amazonaws.services.dynamodbv2.model.AttributeValue;

import java.util.Map;
import java.util.Objects;

@DynamoDBDocument
public class MFAMethod {

    public static final String ATTRIBUTE_MFA_METHOD_TYPE = "MfaMethodType";
    public static final String ATTRIBUTE_CREDENTIAL_VALUE = "CredentialValue";
    public static final String ATTRIBUTE_ENABLED = "Enabled";
    public static final String ATTRIBUTE_METHOD_VERIFIED = "MethodVerified";
    public static final String ATTRIBUTE_UPDATED = "Updated";

    private String mfaMethodType;
    private String credentialValue;
    private boolean methodVerified;
    private boolean enabled;
    private String updated;

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

    @DynamoDBAttribute(attributeName = ATTRIBUTE_MFA_METHOD_TYPE)
    public String getMfaMethodType() {
        return mfaMethodType;
    }

    public MFAMethod setMfaMethodType(String mfaMethodType) {
        this.mfaMethodType = mfaMethodType;
        return this;
    }

    @DynamoDBAttribute(attributeName = ATTRIBUTE_CREDENTIAL_VALUE)
    public String getCredentialValue() {
        return credentialValue;
    }

    public MFAMethod setCredentialValue(String credentialValue) {
        this.credentialValue = credentialValue;
        return this;
    }

    @DynamoDBAttribute(attributeName = ATTRIBUTE_METHOD_VERIFIED)
    public boolean isMethodVerified() {
        return methodVerified;
    }

    public MFAMethod setMethodVerified(boolean methodVerified) {
        this.methodVerified = methodVerified;
        return this;
    }

    @DynamoDBAttribute(attributeName = ATTRIBUTE_ENABLED)
    public boolean isEnabled() {
        return enabled;
    }

    public MFAMethod setEnabled(boolean enabled) {
        this.enabled = enabled;
        return this;
    }

    @DynamoDBAttribute(attributeName = ATTRIBUTE_UPDATED)
    public String getUpdated() {
        return updated;
    }

    public MFAMethod setUpdated(String updated) {
        this.updated = updated;
        return this;
    }

    AttributeValue toAttributeValue() {
        return new AttributeValue()
                .withM(
                        Map.ofEntries(
                                Map.entry(
                                        ATTRIBUTE_MFA_METHOD_TYPE,
                                        new AttributeValue(getMfaMethodType())),
                                Map.entry(
                                        ATTRIBUTE_CREDENTIAL_VALUE,
                                        new AttributeValue(getCredentialValue())),
                                Map.entry(
                                        ATTRIBUTE_METHOD_VERIFIED,
                                        new AttributeValue().withN(isMethodVerified() ? "1" : "0")),
                                Map.entry(
                                        ATTRIBUTE_ENABLED,
                                        new AttributeValue().withN(isEnabled() ? "1" : "0")),
                                Map.entry(ATTRIBUTE_UPDATED, new AttributeValue(getUpdated()))));
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
                && Objects.equals(updated, that.updated);
    }

    @Override
    public int hashCode() {
        return Objects.hash(mfaMethodType, credentialValue, methodVerified, enabled, updated);
    }
}
