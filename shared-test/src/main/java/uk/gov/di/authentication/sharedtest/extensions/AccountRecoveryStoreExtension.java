package uk.gov.di.authentication.sharedtest.extensions;

import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import software.amazon.awssdk.services.dynamodb.model.AttributeDefinition;
import software.amazon.awssdk.services.dynamodb.model.BillingMode;
import software.amazon.awssdk.services.dynamodb.model.CreateTableRequest;
import software.amazon.awssdk.services.dynamodb.model.KeySchemaElement;
import software.amazon.awssdk.services.dynamodb.model.KeyType;
import software.amazon.awssdk.services.dynamodb.model.ScalarAttributeType;
import uk.gov.di.authentication.frontendapi.services.DynamoAccountRecoveryBlockService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.sharedtest.basetest.DynamoTestConfiguration;

public class AccountRecoveryStoreExtension extends DynamoExtension implements AfterEachCallback {

    public static final String EMAIL_FIELD = "Email";
    public static final String ACCOUNT_RECOVERY_BLOCK_TABLE = "local-account-recovery-block";

    private DynamoAccountRecoveryBlockService dynamoAccountRecoveryService;
    private final ConfigurationService configuration;

    public AccountRecoveryStoreExtension(long ttl) {
        createInstance();
        this.configuration =
                new DynamoTestConfiguration(REGION, ENVIRONMENT, DYNAMO_ENDPOINT) {
                    @Override
                    public Long getAccountRecoveryBlockTTL() {
                        return ttl;
                    }
                };
        dynamoAccountRecoveryService = new DynamoAccountRecoveryBlockService(configuration);
    }

    @Override
    public void beforeAll(ExtensionContext context) throws Exception {
        super.beforeAll(context);

        dynamoAccountRecoveryService = new DynamoAccountRecoveryBlockService(configuration);
    }

    @Override
    public void afterEach(ExtensionContext context) throws Exception {
        clearDynamoTable(dynamoDB, ACCOUNT_RECOVERY_BLOCK_TABLE, EMAIL_FIELD);
    }

    public void addBlockWithTTL(String email) {
        dynamoAccountRecoveryService.addBlockWithTTL(email);
    }

    public void addBlockWithoutTTL(String email) {
        dynamoAccountRecoveryService.addBlockWithNoTTL(email);
    }

    @Override
    protected void createTables() {
        if (!tableExists(ACCOUNT_RECOVERY_BLOCK_TABLE)) {
            createAccountRecoveryBlockTable();
        }
    }

    private void createAccountRecoveryBlockTable() {
        CreateTableRequest request =
                CreateTableRequest.builder()
                        .tableName(ACCOUNT_RECOVERY_BLOCK_TABLE)
                        .keySchema(
                                KeySchemaElement.builder()
                                        .keyType(KeyType.HASH)
                                        .attributeName(EMAIL_FIELD)
                                        .build())
                        .attributeDefinitions(
                                AttributeDefinition.builder()
                                        .attributeName(EMAIL_FIELD)
                                        .attributeType(ScalarAttributeType.S)
                                        .build())
                        .billingMode(BillingMode.PAY_PER_REQUEST)
                        .build();

        dynamoDB.createTable(request);
    }
}
