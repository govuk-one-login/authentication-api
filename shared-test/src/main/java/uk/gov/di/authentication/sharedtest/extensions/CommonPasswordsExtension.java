package uk.gov.di.authentication.sharedtest.extensions;

import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.BeforeEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import software.amazon.awssdk.services.dynamodb.model.AttributeDefinition;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.BillingMode;
import software.amazon.awssdk.services.dynamodb.model.CreateTableRequest;
import software.amazon.awssdk.services.dynamodb.model.KeySchemaElement;
import software.amazon.awssdk.services.dynamodb.model.KeyType;
import software.amazon.awssdk.services.dynamodb.model.PutItemRequest;
import software.amazon.awssdk.services.dynamodb.model.ScalarAttributeType;
import uk.gov.di.authentication.shared.services.CommonPasswordsService;
import uk.gov.di.authentication.sharedtest.basetest.DynamoTestConfiguration;

import java.util.Map;

public class CommonPasswordsExtension extends DynamoExtension
        implements AfterEachCallback, BeforeEachCallback {

    public static final String COMMON_PASSWORDS_TABLE = "local-common-passwords";
    public static final String PASSWORD_FIELD = "Password";
    public static final String TEST_COMMON_PASSWORD = "TestCommonPassword1";

    private CommonPasswordsService commonPasswordsService;

    public boolean isCommonPassword(String password) {
        return commonPasswordsService.isCommonPassword(password);
    }

    @Override
    public void beforeAll(ExtensionContext context) throws Exception {
        super.beforeAll(context);
        commonPasswordsService =
                new CommonPasswordsService(
                        new DynamoTestConfiguration(REGION, ENVIRONMENT, LOCALSTACK_ENDPOINT));
    }

    @Override
    public void beforeEach(ExtensionContext context) throws Exception {
        addTestPasswordToCommonPasswordsTable();
    }

    @Override
    public void afterEach(ExtensionContext context) throws Exception {
        clearDynamoTable(dynamoDB, COMMON_PASSWORDS_TABLE, PASSWORD_FIELD);
    }

    @Override
    protected void createTables() {
        if (!tableExists(COMMON_PASSWORDS_TABLE)) {
            createCommonPasswordsTable();
        }
    }

    private void createCommonPasswordsTable() {
        CreateTableRequest request =
                CreateTableRequest.builder()
                        .tableName(COMMON_PASSWORDS_TABLE)
                        .keySchema(
                                KeySchemaElement.builder()
                                        .keyType(KeyType.HASH)
                                        .attributeName(PASSWORD_FIELD)
                                        .build())
                        .billingMode(BillingMode.PAY_PER_REQUEST)
                        .attributeDefinitions(
                                AttributeDefinition.builder()
                                        .attributeName(PASSWORD_FIELD)
                                        .attributeType(ScalarAttributeType.S)
                                        .build())
                        .build();

        dynamoDB.createTable(request);
    }

    private void addTestPasswordToCommonPasswordsTable() {
        PutItemRequest request =
                PutItemRequest.builder()
                        .tableName(COMMON_PASSWORDS_TABLE)
                        .item(Map.of(PASSWORD_FIELD, AttributeValue.fromS(TEST_COMMON_PASSWORD)))
                        .build();

        dynamoDB.putItem(request);
    }
}
