package uk.gov.di.authentication.shared.entity;

import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbAttribute;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbConvertedBy;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import uk.gov.di.authentication.shared.dynamodb.BooleanToIntAttributeConverter;

import java.util.Map;
import java.util.Objects;

@DynamoDbBean
public class AuthAppMFAMethod {

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

    public AuthAppMFAMethod() {}

    public AuthAppMFAMethod(
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

    @DynamoDbAttribute(ATTRIBUTE_MFA_METHOD_TYPE)
    public String getMfaMethodType() {
        return mfaMethodType;
    }

    public void setMfaMethodType(String mfaMethodType) {
        this.mfaMethodType = mfaMethodType;
    }

    public AuthAppMFAMethod withMfaMethodType(String mfaMethodType) {
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

    public AuthAppMFAMethod withCredentialValue(String credentialValue) {
        this.credentialValue = credentialValue;
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

    public AuthAppMFAMethod withMethodVerified(boolean methodVerified) {
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

    public AuthAppMFAMethod withEnabled(boolean enabled) {
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

    public AuthAppMFAMethod withUpdated(String updated) {
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
        AuthAppMFAMethod that = (AuthAppMFAMethod) o;
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
