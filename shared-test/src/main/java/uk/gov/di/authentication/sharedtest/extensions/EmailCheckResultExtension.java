package uk.gov.di.authentication.sharedtest.extensions;

import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import software.amazon.awssdk.services.dynamodb.model.AttributeDefinition;
import software.amazon.awssdk.services.dynamodb.model.BillingMode;
import software.amazon.awssdk.services.dynamodb.model.CreateTableRequest;
import software.amazon.awssdk.services.dynamodb.model.KeySchemaElement;
import software.amazon.awssdk.services.dynamodb.model.KeyType;
import software.amazon.awssdk.services.dynamodb.model.ScalarAttributeType;

public class EmailCheckResultExtension extends DynamoExtension implements AfterEachCallback {

    public static final String EMAIL_CHECK_RESULT_TABLE = "local-email-check-result";

    private static final String EMAIL_FIELD = "Email";

    public EmailCheckResultExtension() {
        createInstance();
    }

    @Override
    public void afterEach(ExtensionContext context) throws Exception {
        clearDynamoTable(dynamoDB, EMAIL_CHECK_RESULT_TABLE, EMAIL_FIELD);
    }

    @Override
    protected void createTables() {
        if (!tableExists(EMAIL_CHECK_RESULT_TABLE)) {
            createEmailCheckResultTable();
        }
    }

    private void createEmailCheckResultTable() {
        CreateTableRequest request =
                CreateTableRequest.builder()
                        .tableName(EMAIL_CHECK_RESULT_TABLE)
                        .keySchema(
                                KeySchemaElement.builder()
                                        .keyType(KeyType.HASH)
                                        .attributeName(EMAIL_FIELD)
                                        .build())
                        .billingMode(BillingMode.PAY_PER_REQUEST)
                        .attributeDefinitions(
                                AttributeDefinition.builder()
                                        .attributeName(EMAIL_FIELD)
                                        .attributeType(ScalarAttributeType.S)
                                        .build())
                        .build();

        dynamoDB.createTable(request);
    }
}
