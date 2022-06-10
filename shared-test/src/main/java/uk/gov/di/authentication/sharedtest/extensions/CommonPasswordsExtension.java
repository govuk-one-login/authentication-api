package uk.gov.di.authentication.sharedtest.extensions;

import com.amazonaws.services.dynamodbv2.model.AttributeDefinition;
import com.amazonaws.services.dynamodbv2.model.AttributeValue;
import com.amazonaws.services.dynamodbv2.model.BillingMode;
import com.amazonaws.services.dynamodbv2.model.CreateTableRequest;
import com.amazonaws.services.dynamodbv2.model.KeySchemaElement;
import com.amazonaws.services.dynamodbv2.model.PutItemRequest;
import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.BeforeEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import uk.gov.di.authentication.shared.services.CommonPasswordsService;
import uk.gov.di.authentication.sharedtest.basetest.DynamoTestConfiguration;

import static com.amazonaws.services.dynamodbv2.model.KeyType.HASH;
import static com.amazonaws.services.dynamodbv2.model.ScalarAttributeType.S;

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
                        new DynamoTestConfiguration(REGION, ENVIRONMENT, DYNAMO_ENDPOINT));
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
                new CreateTableRequest()
                        .withTableName(COMMON_PASSWORDS_TABLE)
                        .withKeySchema(new KeySchemaElement(PASSWORD_FIELD, HASH))
                        .withBillingMode(BillingMode.PAY_PER_REQUEST)
                        .withAttributeDefinitions(new AttributeDefinition(PASSWORD_FIELD, S));

        dynamoDB.createTable(request);
    }

    private void addTestPasswordToCommonPasswordsTable() {
        PutItemRequest request =
                new PutItemRequest()
                        .withTableName(COMMON_PASSWORDS_TABLE)
                        .addItemEntry(PASSWORD_FIELD, new AttributeValue(TEST_COMMON_PASSWORD));

        dynamoDB.putItem(request);
    }
}
