package uk.gov.di.orchestration.sharedtest.basetest;

import org.mockito.ArgumentMatchers;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.enhanced.dynamodb.Key;
import software.amazon.awssdk.enhanced.dynamodb.model.GetItemEnhancedRequest;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.DynamoDbException;
import uk.gov.di.orchestration.shared.services.ConfigurationService;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;

public abstract class BaseDynamoServiceTest<T> {
    protected final DynamoDbTable<T> table = mock(DynamoDbTable.class);
    protected final DynamoDbClient dynamoDbClient = mock(DynamoDbClient.class);
    protected final ConfigurationService configurationService = mock(ConfigurationService.class);

    public static GetItemEnhancedRequest getRequestFor(String partitionKey) {
        return getRequestFor(Key.builder().partitionValue(partitionKey).build());
    }

    public static GetItemEnhancedRequest getRequestFor(String partitionKey, String sortKey) {
        return getRequestFor(Key.builder().partitionValue(partitionKey).sortValue(sortKey).build());
    }

    private static GetItemEnhancedRequest getRequestFor(Key key) {
        return GetItemEnhancedRequest.builder().key(key).consistentRead(true).build();
    }

    protected void withFailedGet() {
        doThrow(DynamoDbException.builder().message("Failed to get item from table").build())
                .when(table)
                .getItem(any(GetItemEnhancedRequest.class));
    }

    protected void withFailedPut() {
        doThrow(DynamoDbException.builder().message("Failed to put item in table").build())
                .when(table)
                .putItem(ArgumentMatchers.<T>any());
    }

    protected void withFailedUpdate() {
        doThrow(DynamoDbException.builder().message("Failed to update item in table").build())
                .when(table)
                .updateItem(ArgumentMatchers.<T>any());
    }

    protected void withFailedDelete() {
        doThrow(DynamoDbException.builder().message("Failed to delete from table").build())
                .when(table)
                .deleteItem(ArgumentMatchers.<T>any());
    }
}
