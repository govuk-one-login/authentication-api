package uk.gov.di.authentication.shared.dynamodb;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import software.amazon.awssdk.enhanced.dynamodb.AttributeConverter;
import software.amazon.awssdk.enhanced.dynamodb.AttributeValueType;
import software.amazon.awssdk.enhanced.dynamodb.EnhancedType;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import uk.gov.di.authentication.shared.entity.MfaMethod;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class MfaMethodListConverter implements AttributeConverter<List<MfaMethod>> {

    private static final Gson gson = new Gson();

    @Override
    public AttributeValue transformFrom(List<MfaMethod> input) {
        if (input == null) {
            return AttributeValue.builder().nul(true).build();
        }
        List<Map<String, String>> serializedList =
                input.stream()
                        .map(
                                obj ->
                                        Map.of(
                                                "type", obj.getClass().getName(),
                                                "data", gson.toJson(obj)))
                        .collect(Collectors.toList());
        String json = gson.toJson(serializedList);
        return AttributeValue.builder().s(json).build();
    }

    @Override
    public List<MfaMethod> transformTo(AttributeValue input) {
        if (input == null || input.s() == null || input.s().isEmpty()) {
            return new ArrayList<>(); // Return an empty list if the input is null or empty
        }

        String json = input.s();
        List<Map<String, String>> deserializedList =
                gson.fromJson(json, new TypeToken<List<Map<String, String>>>() {}.getType());
        List<MfaMethod> result = new ArrayList<>();
        for (Map<String, String> item : deserializedList) {
            String type = item.get("type");
            String data = item.get("data");
            try {
                Class<?> clazz = Class.forName(type);
                MfaMethod obj = (MfaMethod) gson.fromJson(data, clazz);
                result.add(obj);
            } catch (ClassNotFoundException e) {
                throw new RuntimeException("Failed to deserialize MyInterface", e);
            }
        }
        return result;
    }

    @Override
    public EnhancedType<List<MfaMethod>> type() {
        return EnhancedType.listOf(EnhancedType.of(MfaMethod.class));
    }

    @Override
    public AttributeValueType attributeValueType() {
        return AttributeValueType.L;
    }
}
