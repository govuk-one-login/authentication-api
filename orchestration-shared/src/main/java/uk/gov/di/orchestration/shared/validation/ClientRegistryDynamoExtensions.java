package uk.gov.di.orchestration.shared.validation;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbEnhancedClientExtension;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbExtensionContext;
import software.amazon.awssdk.enhanced.dynamodb.extensions.ReadModification;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbAttribute;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import uk.gov.di.orchestration.shared.entity.ClientRegistry;

import java.util.Arrays;

public class ClientRegistryDynamoExtensions implements DynamoDbEnhancedClientExtension {
    private static final Logger LOG = LogManager.getLogger(ClientRegistryDynamoExtensions.class);

    @Override
    public ReadModification afterRead(DynamoDbExtensionContext.AfterRead context) {

        if (context.items() == null) {
            return ReadModification.builder().build();
        }

        var itemFields = context.items().keySet();
        var validClientFieldAttributeNames =
                Arrays.stream(ClientRegistry.class.getDeclaredMethods())
                        .filter(f -> f.isAnnotationPresent(DynamoDbAttribute.class))
                        .map(f -> f.getDeclaredAnnotation(DynamoDbAttribute.class))
                        .map(DynamoDbAttribute::value)
                        .toList();

        itemFields.forEach(
                key -> {
                    if (!validClientFieldAttributeNames.contains(key)) {
                        LOG.warn(
                                String.format(
                                        "Unknown key: %s present in client with ID: %s",
                                        key,
                                        context.items()
                                                // This should always be present as it is our PK but
                                                // this is just extra safety
                                                // Worst case scenario we can scan for the invalid
                                                // key being present and work
                                                // backwards
                                                .getOrDefault(
                                                        "ClientID", AttributeValue.fromS("unknown"))
                                                .s()));
                    }
                });
        // Return no transformedItem on the ReadModification. This will ensure that the item
        // that is supplied further down is the same item as before.
        return ReadModification.builder().build();
    }
}
