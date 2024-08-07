package uk.gov.di.authentication.shared.entity;

import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbAttribute;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbConvertedBy;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import uk.gov.di.authentication.shared.dynamodb.BooleanToIntAttributeConverter;

import java.util.Map;
import java.util.Objects;

@DynamoDbBean
public class MFAMethodV2 {

    public static final String ATTRIBUTE_MFA_IDENTIFIER = "MfaIdentifier";
    public static final String ATTRIBUTE_PRIORITY_IDENTIFIER = "PriorityIdentifier";
    public static final String ATTRIBUTE_MFA_METHOD_TYPE = "MfaMethodType";
    public static final String ATTRIBUTE_END_POINT = "EndPoint";
    public static final String ATTRIBUTE_METHOD_VERIFIED = "MethodVerified";
    public static final String ATTRIBUTE_ENABLED = "Enabled";
    public static final String ATTRIBUTE_UPDATED = "Updated";

    private String mfaMethodType;
    private boolean methodVerified;
    private boolean enabled;
    private String updated;
    private int mfaIdentifier;
    private PriorityIdentifier priorityIdentifier;
    private String endPoint;

    public MFAMethodV2() {}

    public MFAMethodV2(
            int mfaIdentifier,
            PriorityIdentifier priorityIdentifier,
            String mfaMethodType,
            String endPoint,
            boolean methodVerified,
            boolean enabled,
            String updated) {
        this.mfaMethodType = mfaMethodType;
        this.methodVerified = methodVerified;
        this.enabled = enabled;
        this.updated = updated;
        this.mfaIdentifier = mfaIdentifier;
        this.priorityIdentifier = priorityIdentifier;
        this.endPoint = endPoint;
    }

    @DynamoDbAttribute(ATTRIBUTE_MFA_METHOD_TYPE)
    public String getMfaMethodType() {
        return mfaMethodType;
    }

    public void setMfaMethodType(String mfaMethodType) {
        this.mfaMethodType = mfaMethodType;
    }

    @DynamoDbConvertedBy(BooleanToIntAttributeConverter.class)
    @DynamoDbAttribute(ATTRIBUTE_METHOD_VERIFIED)
    public boolean isMethodVerified() {
        return methodVerified;
    }

    public void setMethodVerified(boolean methodVerified) {
        this.methodVerified = methodVerified;
    }

    @DynamoDbConvertedBy(BooleanToIntAttributeConverter.class)
    @DynamoDbAttribute(ATTRIBUTE_ENABLED)
    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    @DynamoDbAttribute(ATTRIBUTE_UPDATED)
    public String getUpdated() {
        return updated;
    }

    public void setUpdated(String updated) {
        this.updated = updated;
    }

    @DynamoDbAttribute(ATTRIBUTE_MFA_IDENTIFIER)
    public int getMfaIdentifier() {
        return mfaIdentifier;
    }

    public void setMfaIdentifier(int mfaIdentifier) {
        this.mfaIdentifier = mfaIdentifier;
    }

    @DynamoDbAttribute(ATTRIBUTE_PRIORITY_IDENTIFIER)
    public PriorityIdentifier getPriorityIdentifier() {
        return priorityIdentifier;
    }

    public void setPriorityIdentifier(PriorityIdentifier priorityIdentifier) {
        this.priorityIdentifier = priorityIdentifier;
    }

    @DynamoDbAttribute(ATTRIBUTE_END_POINT)
    public String getEndPoint() {
        return endPoint;
    }

    public void setEndPoint(String endPoint) {
        this.endPoint = endPoint;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        MFAMethodV2 that = (MFAMethodV2) o;
        return Objects.equals(mfaMethodType, that.mfaMethodType)
                && Objects.equals(methodVerified, that.methodVerified)
                && Objects.equals(enabled, that.enabled)
                && Objects.equals(updated, that.updated)
                && Objects.equals(mfaIdentifier, that.mfaIdentifier)
                && Objects.equals(priorityIdentifier, that.priorityIdentifier)
                && Objects.equals(endPoint, that.endPoint);
    }

    @Override
    public int hashCode() {
        return Objects.hash(
                mfaIdentifier,
                priorityIdentifier,
                mfaMethodType,
                endPoint,
                methodVerified,
                enabled,
                updated);
    }

    AttributeValue toAttributeValue() {
        return AttributeValue.fromM(
                Map.ofEntries(
                        Map.entry(
                                ATTRIBUTE_MFA_METHOD_TYPE,
                                AttributeValue.fromS(getMfaMethodType())),
                        Map.entry(
                                ATTRIBUTE_METHOD_VERIFIED,
                                AttributeValue.fromN(isMethodVerified() ? "1" : "0")),
                        Map.entry(ATTRIBUTE_ENABLED, AttributeValue.fromN(isEnabled() ? "1" : "0")),
                        Map.entry(ATTRIBUTE_UPDATED, AttributeValue.fromS(getUpdated())),
                        Map.entry(
                                ATTRIBUTE_MFA_IDENTIFIER,
                                AttributeValue.builder()
                                        .n(String.valueOf(getMfaIdentifier()))
                                        .build()),
                        Map.entry(
                                ATTRIBUTE_PRIORITY_IDENTIFIER,
                                AttributeValue.fromS(getPriorityIdentifier().getValue())),
                        Map.entry(ATTRIBUTE_END_POINT, AttributeValue.fromS(getEndPoint()))));
    }
}
