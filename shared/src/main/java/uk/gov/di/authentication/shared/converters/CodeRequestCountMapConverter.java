package uk.gov.di.authentication.shared.converters;

import software.amazon.awssdk.enhanced.dynamodb.AttributeConverter;
import software.amazon.awssdk.enhanced.dynamodb.AttributeValueType;
import software.amazon.awssdk.enhanced.dynamodb.EnhancedType;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import uk.gov.di.authentication.shared.entity.CodeRequestType;

import java.util.Map;
import java.util.stream.Collectors;

public class CodeRequestCountMapConverter
        implements AttributeConverter<Map<CodeRequestType, Integer>> {

    @Override
    public AttributeValue transformFrom(Map<CodeRequestType, Integer> input) {
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
    public Map<CodeRequestType, Integer> transformTo(AttributeValue input) {
        return input.m().entrySet().stream()
                .map(
                        entry ->
                                Map.entry(
                                        CodeRequestType.valueOf(entry.getKey()),
                                        Integer.parseInt(entry.getValue().n())))
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
    }

    @Override
    public EnhancedType<Map<CodeRequestType, Integer>> type() {
        return EnhancedType.mapOf(CodeRequestType.class, Integer.class);
    }

    @Override
    public AttributeValueType attributeValueType() {
        return AttributeValueType.M;
    }
}
