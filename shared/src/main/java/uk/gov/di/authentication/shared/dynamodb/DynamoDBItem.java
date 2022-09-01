package uk.gov.di.authentication.shared.dynamodb;

import software.amazon.awssdk.services.dynamodb.model.AttributeValue;

public interface DynamoDBItem {
    java.util.Map<String, AttributeValue> toItem();
}
