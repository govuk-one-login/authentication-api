package uk.gov.di.authentication.shared.services;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbEnhancedClient;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.enhanced.dynamodb.Key;
import software.amazon.awssdk.enhanced.dynamodb.TableSchema;
import software.amazon.awssdk.enhanced.dynamodb.model.BatchWriteItemEnhancedRequest;
import software.amazon.awssdk.enhanced.dynamodb.model.WriteBatch;
import uk.gov.di.authentication.shared.entity.CommonPassword;
import uk.gov.di.authentication.shared.helpers.TableNameHelper;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

import static uk.gov.di.authentication.shared.dynamodb.DynamoClientHelper.createDynamoEnhancedClient;

public class CommonPasswordsService {
    private static final Logger LOG = LogManager.getLogger(CommonPasswordsService.class);
    private static final String COMMON_PASSWORDS_TABLE = "common-passwords";
    private final DynamoDbTable<CommonPassword> dynamoCommonPasswordTable;
    private final DynamoDbEnhancedClient dynamoDbEnhancedClient;

    public CommonPasswordsService(ConfigurationService configurationService) {
        String tableName =
                TableNameHelper.getFullTableName(COMMON_PASSWORDS_TABLE, configurationService);
        dynamoDbEnhancedClient = createDynamoEnhancedClient(configurationService);
        this.dynamoCommonPasswordTable =
                dynamoDbEnhancedClient.table(tableName, TableSchema.fromBean(CommonPassword.class));
        warmUp();
    }

    public boolean isCommonPassword(String password) {
        return dynamoCommonPasswordTable.getItem(Key.builder().partitionValue(password).build())
                != null;
    }

    public void addBatchCommonPasswords(List<String> passwords) {
        var commonPasswords =
                passwords.stream()
                        .map(password -> new CommonPassword().withPassword(password))
                        .collect(Collectors.toList());
        LOG.info("Add common passwords batch method called with {} items", commonPasswords.size());

        int maxBatchWriteItems = 25;
        List<List<CommonPassword>> partitions = new ArrayList<>();

        for (int i = 0; i < commonPasswords.size(); i += maxBatchWriteItems) {
            partitions.add(
                    commonPasswords.subList(
                            i, Math.min(i + maxBatchWriteItems, commonPasswords.size())));
        }

        for (List<CommonPassword> commonPasswordsBatch : partitions) {

            var writeBatchBuilder =
                    WriteBatch.builder(CommonPassword.class)
                            .mappedTableResource(dynamoCommonPasswordTable);
            commonPasswordsBatch.forEach(t -> writeBatchBuilder.addPutItem(e -> e.item(t)));
            WriteBatch writeBatch = writeBatchBuilder.build();
            var result =
                    dynamoDbEnhancedClient.batchWriteItem(
                            BatchWriteItemEnhancedRequest.builder()
                                    .writeBatches(writeBatch)
                                    .build());

            List<CommonPassword> unprocessedCommonPasswordPutItems =
                    result.unprocessedPutItemsForTable(dynamoCommonPasswordTable);
            if (Objects.nonNull(unprocessedCommonPasswordPutItems)
                    && !unprocessedCommonPasswordPutItems.isEmpty()) {
                LOG.error(
                        "Dynamo batch write returned failed batch, with {} failed batches",
                        unprocessedCommonPasswordPutItems.size());

                unprocessedCommonPasswordPutItems.forEach(
                        t -> LOG.error("Error produced by write request: {}", t.getPassword()));

                LOG.error("Batch write failed");
            }
        }
    }

    private void warmUp() {
        dynamoCommonPasswordTable.describeTable();
    }
}
