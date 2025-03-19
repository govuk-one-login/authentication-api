package uk.gov.di.authentication.shared.converters;

import software.amazon.awssdk.enhanced.dynamodb.AttributeConverter;
import software.amazon.awssdk.enhanced.dynamodb.AttributeValueType;
import software.amazon.awssdk.enhanced.dynamodb.EnhancedType;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import uk.gov.di.authentication.shared.entity.CountType;

import java.util.Map;
import java.util.stream.Collectors;

public class PreservedReauthCountsForAuditMapConverter
        implements AttributeConverter<Map<CountType, Integer>> {

    @Override
    public AttributeValue transformFrom(Map<CountType, Integer> input) {
        return AttributeValue.fromM(
                input.entrySet().stream()
                        .map(
                                entry ->
                                        Map.entry(
                                                entry.getKey().name(),
                                                AttributeValue.fromN(entry.getValue().toString())))
                        .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue)));
    }

    @Override
    public Map<CountType, Integer> transformTo(AttributeValue input) {
        return input.m().entrySet().stream()
                .map(
                        entry ->
                                Map.entry(
                                        CountType.valueOf(entry.getKey()),
                                        Integer.parseInt(entry.getValue().n())))
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
    }

    @Override
    public EnhancedType<Map<CountType, Integer>> type() {
        return EnhancedType.mapOf(CountType.class, Integer.class);
    }

    @Override
    public AttributeValueType attributeValueType() {
        return AttributeValueType.M;
    }
}
