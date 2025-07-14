package uk.gov.di.orchestration.shared.services;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbEnhancedClient;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.enhanced.dynamodb.Key;
import software.amazon.awssdk.enhanced.dynamodb.TableSchema;
import software.amazon.awssdk.enhanced.dynamodb.model.GetItemEnhancedRequest;
import software.amazon.awssdk.enhanced.dynamodb.model.QueryConditional;
import software.amazon.awssdk.enhanced.dynamodb.model.QueryEnhancedRequest;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.DescribeTableRequest;
import software.amazon.awssdk.services.dynamodb.model.DescribeTableResponse;
import software.amazon.awssdk.services.dynamodb.model.QueryRequest;
import software.amazon.awssdk.services.dynamodb.model.QueryResponse;
import uk.gov.di.orchestration.shared.helpers.TableNameHelper;

import java.util.List;
import java.util.Optional;

import static uk.gov.di.orchestration.shared.dynamodb.DynamoClientHelper.createDynamoClient;

public class BaseDynamoService<T> {
    private static final Logger LOG = LogManager.getLogger(BaseDynamoService.class);
    private final DynamoDbTable<T> dynamoTable;
    private final DynamoDbClient client;
    private final boolean useConsistentReads;

    public BaseDynamoService(
            Class<T> objectClass, String table, ConfigurationService configurationService) {
        this(objectClass, table, configurationService, false);
    }

    public BaseDynamoService(
            Class<T> objectClass,
            String table,
            ConfigurationService configurationService,
            boolean isTableInOrchAccount) {

        var tableName =
                TableNameHelper.getFullTableName(table, configurationService, isTableInOrchAccount);

        client = createDynamoClient(configurationService);
        var enhancedClient = DynamoDbEnhancedClient.builder().dynamoDbClient(client).build();
        dynamoTable = enhancedClient.table(tableName, TableSchema.fromBean(objectClass));
        useConsistentReads = configurationService.isUseStronglyConsistentReads();
        LOG.info(
                "Is using strongly consistent reads for table \"{}\": {}",
                table,
                useConsistentReads);
        if (!isTableInOrchAccount) {
            warmUp();
        }
    }

    public BaseDynamoService(
            DynamoDbTable<T> dynamoTable,
            DynamoDbClient client,
            ConfigurationService configurationService) {
        this.dynamoTable = dynamoTable;
        this.client = client;
        this.useConsistentReads = configurationService.isUseStronglyConsistentReads();
    }

    public void update(T item) {
        dynamoTable.updateItem(item);
    }

    public void put(T item) {
        dynamoTable.putItem(item);
    }

    public Optional<T> get(String partition) {
        return get(Key.builder().partitionValue(partition).build());
    }

    public Optional<T> get(String partition, String sort) {
        return get(Key.builder().partitionValue(partition).sortValue(sort).build());
    }

    private Optional<T> get(Key key) {
        return Optional.ofNullable(
                dynamoTable.getItem(
                        GetItemEnhancedRequest.builder()
                                .consistentRead(useConsistentReads)
                                .key(key)
                                .build()));
    }

    public Optional<T> getWithConsistentRead(String partition) {
        return Optional.ofNullable(
                dynamoTable.getItem(
                        GetItemEnhancedRequest.builder()
                                .consistentRead(true)
                                .key(Key.builder().partitionValue(partition).build())
                                .build()));
    }

    public Optional<T> getWithConsistentRead(String partition, String sort) {
        return Optional.ofNullable(
                dynamoTable.getItem(
                        GetItemEnhancedRequest.builder()
                                .consistentRead(true)
                                .key(
                                        Key.builder()
                                                .partitionValue(partition)
                                                .sortValue(sort)
                                                .build())
                                .build()));
    }

    public List<T> queryIndex(String indexName, String partition) {
        QueryConditional q =
                QueryConditional.keyEqualTo(Key.builder().partitionValue(partition).build());
        return dynamoTable
                .index(indexName)
                .query(QueryEnhancedRequest.builder().queryConditional(q).build())
                .stream()
                .flatMap(page -> page.items().stream())
                .toList();
    }

    public void delete(String partition) {
        get(partition).ifPresent(dynamoTable::deleteItem);
    }

    private void warmUp() {
        dynamoTable.describeTable();
    }

    public QueryResponse query(QueryRequest request) {
        return client.query(request);
    }

    public DescribeTableResponse describeTable() {
        return client.describeTable(
                DescribeTableRequest.builder().tableName(dynamoTable.tableName()).build());
    }
}
