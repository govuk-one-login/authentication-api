package uk.gov.di.orchestration.shared.dynamodb;

import software.amazon.awssdk.enhanced.dynamodb.DynamoDbEnhancedClientExtension;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbExtensionContext;
import software.amazon.awssdk.enhanced.dynamodb.extensions.WriteModification;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;

import static uk.gov.di.orchestration.shared.entity.LevelOfConfidence.HIGH_LEVEL;
import static uk.gov.di.orchestration.shared.entity.LevelOfConfidence.LOW_LEVEL;

public class SelfServiceClientRegistryExtension implements DynamoDbEnhancedClientExtension {
    private static final List<String> manuallyConfiguredLocValues =
            List.of(LOW_LEVEL.getValue(), HIGH_LEVEL.getValue());

    @Override
    public WriteModification beforeWrite(DynamoDbExtensionContext.BeforeWrite context) {
        var clientItem = context.items();

        if (clientItem == null) {
            return WriteModification.builder().build();
        }

        if (!clientItem.containsKey("ClientLoCs")) {
            return WriteModification.builder().build();
        }

        if (clientItem.get("ClientLoCs").l().stream()
                .anyMatch(loc -> manuallyConfiguredLocValues.contains(loc.s()))) {
            // Do not modify if the client contains manually configured values
            return WriteModification.builder().build();
        }
        var modifiedClient = new HashMap<>(clientItem);
        modifiedClient.put("ClientLoCs", AttributeValue.fromL(Collections.emptyList()));
        return WriteModification.builder().transformedItem(modifiedClient).build();
    }
}
