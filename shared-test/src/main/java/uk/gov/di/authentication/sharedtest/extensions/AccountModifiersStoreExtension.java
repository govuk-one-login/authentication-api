package uk.gov.di.authentication.sharedtest.extensions;

import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import software.amazon.awssdk.services.dynamodb.model.AttributeDefinition;
import software.amazon.awssdk.services.dynamodb.model.BillingMode;
import software.amazon.awssdk.services.dynamodb.model.CreateTableRequest;
import software.amazon.awssdk.services.dynamodb.model.KeySchemaElement;
import software.amazon.awssdk.services.dynamodb.model.KeyType;
import software.amazon.awssdk.services.dynamodb.model.ScalarAttributeType;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoAccountModifiersService;
import uk.gov.di.authentication.sharedtest.basetest.DynamoTestConfiguration;

public class AccountModifiersStoreExtension extends DynamoExtension implements AfterEachCallback {

    public static final String INTERNAL_COMMON_SUBJECT_ID = "InternalCommonSubjectIdentifier";
    public static final String ACCOUNT_MODIFIERS_TABLE = "local-account-modifiers";

    private DynamoAccountModifiersService dynamoAccountModifiersService;
    private final ConfigurationService configuration;

    public AccountModifiersStoreExtension() {
        createInstance();
        this.configuration = new DynamoTestConfiguration(REGION, ENVIRONMENT, LOCALSTACK_ENDPOINT);
        dynamoAccountModifiersService = new DynamoAccountModifiersService(configuration);
    }

    @Override
    public void beforeAll(ExtensionContext context) throws Exception {
        super.beforeAll(context);

        dynamoAccountModifiersService = new DynamoAccountModifiersService(configuration);
    }

    @Override
    public void afterEach(ExtensionContext context) throws Exception {
        clearDynamoTable(dynamoDB, ACCOUNT_MODIFIERS_TABLE, INTERNAL_COMMON_SUBJECT_ID);
    }

    public boolean isBlockPresent(String internalCommonSubjectId) {
        return dynamoAccountModifiersService.isAccountRecoveryBlockPresent(internalCommonSubjectId);
    }

    public boolean isEntryForSubjectIdPresent(String internalCommonSubjectId) {
        return dynamoAccountModifiersService
                .getAccountModifiers(internalCommonSubjectId)
                .isPresent();
    }

    public void setAccountRecoveryBlock(String internalCommonSubjectId) {
        dynamoAccountModifiersService.setAccountRecoveryBlock(internalCommonSubjectId, true);
    }

    @Override
    protected void createTables() {
        if (!tableExists(ACCOUNT_MODIFIERS_TABLE)) {
            createAccountRecoveryBlockTable();
        }
    }

    private void createAccountRecoveryBlockTable() {
        var request =
                CreateTableRequest.builder()
                        .tableName(ACCOUNT_MODIFIERS_TABLE)
                        .keySchema(
                                KeySchemaElement.builder()
                                        .keyType(KeyType.HASH)
                                        .attributeName(INTERNAL_COMMON_SUBJECT_ID)
                                        .build())
                        .attributeDefinitions(
                                AttributeDefinition.builder()
                                        .attributeName(INTERNAL_COMMON_SUBJECT_ID)
                                        .attributeType(ScalarAttributeType.S)
                                        .build())
                        .billingMode(BillingMode.PAY_PER_REQUEST)
                        .build();

        dynamoDB.createTable(request);
    }
}
