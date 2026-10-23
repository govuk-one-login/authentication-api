package uk.gov.di.authentication.sharedtest.extensions;

import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import software.amazon.awssdk.services.dynamodb.model.AttributeDefinition;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.BillingMode;
import software.amazon.awssdk.services.dynamodb.model.CreateTableRequest;
import software.amazon.awssdk.services.dynamodb.model.KeySchemaElement;
import software.amazon.awssdk.services.dynamodb.model.KeyType;
import software.amazon.awssdk.services.dynamodb.model.PutItemRequest;
import software.amazon.awssdk.services.dynamodb.model.ScalarAttributeType;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

public class LastSignedInTrackerExtension extends DynamoExtension implements AfterEachCallback {

    public static final String TRACKER_TABLE = "local-last-signed-in-tracker";
    public static final String PARTITION_KEY = "dateForDeletion";
    public static final String SORT_KEY = "commonSubjectId";
    private static final String DEFAULT_DATE_FOR_DELETION = "2031-06-01";

    public LastSignedInTrackerExtension() {
        createInstance();
    }

    @Override
    public void afterEach(ExtensionContext context) throws Exception {
        clearDynamoTable(dynamoDB, TRACKER_TABLE, PARTITION_KEY, Optional.of(SORT_KEY));
    }

    @Override
    protected void createTables() {
        if (!tableExists(TRACKER_TABLE)) {
            createTrackerTable();
        }
    }

    private void createTrackerTable() {
        dynamoDB.createTable(
                CreateTableRequest.builder()
                        .tableName(TRACKER_TABLE)
                        .keySchema(
                                KeySchemaElement.builder()
                                        .attributeName(PARTITION_KEY)
                                        .keyType(KeyType.HASH)
                                        .build(),
                                KeySchemaElement.builder()
                                        .attributeName(SORT_KEY)
                                        .keyType(KeyType.RANGE)
                                        .build())
                        .attributeDefinitions(
                                AttributeDefinition.builder()
                                        .attributeName(PARTITION_KEY)
                                        .attributeType(ScalarAttributeType.S)
                                        .build(),
                                AttributeDefinition.builder()
                                        .attributeName(SORT_KEY)
                                        .attributeType(ScalarAttributeType.S)
                                        .build())
                        .billingMode(BillingMode.PAY_PER_REQUEST)
                        .build());
    }

    public void addTrackerItem(String email, String userLastActive) {
        Map<String, AttributeValue> item = new HashMap<>();
        item.put(PARTITION_KEY, AttributeValue.fromS(DEFAULT_DATE_FOR_DELETION));
        item.put(SORT_KEY, AttributeValue.fromS("csid-" + email));
        item.put("emailAddress", AttributeValue.fromS(email));
        item.put("userLastActive", AttributeValue.fromS(userLastActive));
        dynamoDB.putItem(PutItemRequest.builder().tableName(TRACKER_TABLE).item(item).build());
    }

    public void addTrackerItemWithoutEmail(String userLastActive) {
        Map<String, AttributeValue> item = new HashMap<>();
        item.put(PARTITION_KEY, AttributeValue.fromS(DEFAULT_DATE_FOR_DELETION));
        item.put(SORT_KEY, AttributeValue.fromS("csid-no-email"));
        item.put("userLastActive", AttributeValue.fromS(userLastActive));
        dynamoDB.putItem(PutItemRequest.builder().tableName(TRACKER_TABLE).item(item).build());
    }

    public void addTrackerItemWithoutUserLastActive(String email) {
        Map<String, AttributeValue> item = new HashMap<>();
        item.put(PARTITION_KEY, AttributeValue.fromS(DEFAULT_DATE_FOR_DELETION));
        item.put(SORT_KEY, AttributeValue.fromS("csid-" + email));
        item.put("emailAddress", AttributeValue.fromS(email));
        dynamoDB.putItem(PutItemRequest.builder().tableName(TRACKER_TABLE).item(item).build());
    }
}
