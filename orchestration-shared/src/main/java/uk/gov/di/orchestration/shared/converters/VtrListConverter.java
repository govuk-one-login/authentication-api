package uk.gov.di.orchestration.shared.converters;

import software.amazon.awssdk.enhanced.dynamodb.AttributeConverter;
import software.amazon.awssdk.enhanced.dynamodb.AttributeValueType;
import software.amazon.awssdk.enhanced.dynamodb.EnhancedType;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import uk.gov.di.orchestration.shared.entity.VectorOfTrust;
import uk.gov.di.orchestration.shared.services.SerializationService;

import java.util.List;

public class VtrListConverter implements AttributeConverter<List<VectorOfTrust>> {
    private final SerializationService serializationService = SerializationService.getInstance();

    @Override
    public AttributeValue transformFrom(List<VectorOfTrust> input) {
        return AttributeValue.fromL(
                input.stream()
                        .map(serializationService::writeValueAsString)
                        .map(AttributeValue::fromS)
                        .toList());
    }

    @Override
    public List<VectorOfTrust> transformTo(AttributeValue input) {
        return input.l().stream()
                .map(
                        value ->
                                serializationService.readValueUnchecked(
                                        value.s(), VectorOfTrust.class))
                .toList();
    }

    @Override
    public EnhancedType<List<VectorOfTrust>> type() {
        return EnhancedType.listOf(VectorOfTrust.class);
    }

    @Override
    public AttributeValueType attributeValueType() {
        return AttributeValueType.L;
    }
}
