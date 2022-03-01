package uk.gov.di.authentication.shared.dynamodb;

import com.amazonaws.services.dynamodbv2.model.AttributeValue;

public interface DynamoDBItem {
    public java.util.Map<String, AttributeValue> toItem();
}
