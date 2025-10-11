package uk.gov.di.authentication.shared.converters;

import software.amazon.awssdk.enhanced.dynamodb.AttributeConverter;
import software.amazon.awssdk.enhanced.dynamodb.AttributeValueType;
import software.amazon.awssdk.enhanced.dynamodb.EnhancedType;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import uk.gov.di.authentication.shared.entity.EmailCheckResponse;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.SerializationService;

public class EmailCheckResponseConverter implements AttributeConverter<EmailCheckResponse> {

    private static final SerializationService serializationService =
            SerializationService.getInstance();

    @Override
    public AttributeValue transformFrom(EmailCheckResponse input) {
        if (input == null) {
            return AttributeValue.builder().nul(true).build();
        }
        return AttributeValue.builder().s(serializationService.writeValueAsString(input)).build();
    }

    @Override
    public EmailCheckResponse transformTo(AttributeValue input) {
        if (input.nul() != null && input.nul()) {
            return null;
        }
        try {
            return serializationService.readValue(input.s(), EmailCheckResponse.class);
        } catch (Json.JsonException e) {
            throw new RuntimeException("Failed to deserialize EmailCheckResponse", e);
        }
    }

    @Override
    public EnhancedType<EmailCheckResponse> type() {
        return EnhancedType.of(EmailCheckResponse.class);
    }

    @Override
    public AttributeValueType attributeValueType() {
        return AttributeValueType.S;
    }
}
