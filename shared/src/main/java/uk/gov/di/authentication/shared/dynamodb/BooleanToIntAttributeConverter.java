package uk.gov.di.authentication.shared.dynamodb;

import software.amazon.awssdk.enhanced.dynamodb.AttributeConverter;
import software.amazon.awssdk.enhanced.dynamodb.AttributeValueType;
import software.amazon.awssdk.enhanced.dynamodb.EnhancedType;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;

public class BooleanToIntAttributeConverter implements AttributeConverter<Boolean> {

    @Override
    public AttributeValue transformFrom(Boolean input) {
        return AttributeValue.fromN(Boolean.TRUE.equals(input) ? "1" : "0");
    }

    @Override
    public Boolean transformTo(AttributeValue input) {
        return input.n().equals("1");
    }

    @Override
    public EnhancedType<Boolean> type() {
        return EnhancedType.of(Boolean.class);
    }

    @Override
    public AttributeValueType attributeValueType() {
        return AttributeValueType.N;
    }
}
