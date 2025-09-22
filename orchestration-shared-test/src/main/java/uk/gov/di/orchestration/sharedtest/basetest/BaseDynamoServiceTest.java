package uk.gov.di.orchestration.sharedtest.basetest;

import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import uk.gov.di.orchestration.shared.services.ConfigurationService;

import static org.mockito.Mockito.mock;

public abstract class BaseDynamoServiceTest<T> {
    protected final DynamoDbTable<T> table = mock(DynamoDbTable.class);
    protected final DynamoDbClient dynamoDbClient = mock(DynamoDbClient.class);
    protected final ConfigurationService configurationService = mock(ConfigurationService.class);
}
