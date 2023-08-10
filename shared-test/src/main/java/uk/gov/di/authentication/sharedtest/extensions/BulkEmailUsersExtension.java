package uk.gov.di.authentication.sharedtest.extensions;

import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import software.amazon.awssdk.services.dynamodb.model.AttributeDefinition;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.BillingMode;
import software.amazon.awssdk.services.dynamodb.model.CreateTableRequest;
import software.amazon.awssdk.services.dynamodb.model.GlobalSecondaryIndex;
import software.amazon.awssdk.services.dynamodb.model.KeySchemaElement;
import software.amazon.awssdk.services.dynamodb.model.KeyType;
import software.amazon.awssdk.services.dynamodb.model.ProjectionType;
import software.amazon.awssdk.services.dynamodb.model.PutItemRequest;
import software.amazon.awssdk.services.dynamodb.model.ScalarAttributeType;
import uk.gov.di.authentication.shared.entity.BulkEmailStatus;

import java.util.Map;

public class BulkEmailUsersExtension extends DynamoExtension implements AfterEachCallback {

    public static final String SUBJECT_ID_FIELD = "SubjectID";
    public static final String BULK_EMAIL_STATUS_FIELD = "BulkEmailStatus";
    public static final String BULK_EMAIL_STATUS_INDEX = "BulkEmailStatusIndex";

    public static final String BULK_EMAIL_USERS_TABLE = "local-bulk-email-users";

    public BulkEmailUsersExtension() {
        createInstance();
    }

    @Override
    public void afterEach(ExtensionContext context) throws Exception {
        clearDynamoTable(dynamoDB, BULK_EMAIL_USERS_TABLE, SUBJECT_ID_FIELD);
    }

    @Override
    protected void createTables() {
        if (!tableExists(BULK_EMAIL_USERS_TABLE)) {
            createBulkEmailUsersTable();
        }
    }

    private void createBulkEmailUsersTable() {
        CreateTableRequest request =
                CreateTableRequest.builder()
                        .tableName(BULK_EMAIL_USERS_TABLE)
                        .keySchema(
                                KeySchemaElement.builder()
                                        .keyType(KeyType.HASH)
                                        .attributeName(SUBJECT_ID_FIELD)
                                        .build())
                        .billingMode(BillingMode.PAY_PER_REQUEST)
                        .attributeDefinitions(
                                AttributeDefinition.builder()
                                        .attributeName(SUBJECT_ID_FIELD)
                                        .attributeType(ScalarAttributeType.S)
                                        .build(),
                                AttributeDefinition.builder()
                                        .attributeName(BULK_EMAIL_STATUS_FIELD)
                                        .attributeType(ScalarAttributeType.S)
                                        .build())
                        .globalSecondaryIndexes(
                                GlobalSecondaryIndex.builder()
                                        .indexName(BULK_EMAIL_STATUS_INDEX)
                                        .keySchema(
                                                KeySchemaElement.builder()
                                                        .attributeName(BULK_EMAIL_STATUS_FIELD)
                                                        .keyType(KeyType.HASH)
                                                        .build())
                                        .projection(t -> t.projectionType(ProjectionType.ALL))
                                        .build())
                        .build();

        dynamoDB.createTable(request);
    }

    public void addBulkEmailUser(String subjectID, BulkEmailStatus bulkEmailStatus) {
        PutItemRequest request =
                PutItemRequest.builder()
                        .tableName(BULK_EMAIL_USERS_TABLE)
                        .item(
                                Map.of(
                                        SUBJECT_ID_FIELD,
                                        AttributeValue.fromS(subjectID),
                                        BULK_EMAIL_STATUS_FIELD,
                                        AttributeValue.fromS(bulkEmailStatus.toString())))
                        .build();

        dynamoDB.putItem(request);
    }
}
