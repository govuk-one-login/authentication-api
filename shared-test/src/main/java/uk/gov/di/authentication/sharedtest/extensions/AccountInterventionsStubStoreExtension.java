package uk.gov.di.authentication.sharedtest.extensions;

import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import software.amazon.awssdk.services.dynamodb.model.AttributeDefinition;
import software.amazon.awssdk.services.dynamodb.model.BillingMode;
import software.amazon.awssdk.services.dynamodb.model.CreateTableRequest;
import software.amazon.awssdk.services.dynamodb.model.KeySchemaElement;
import software.amazon.awssdk.services.dynamodb.model.KeyType;
import software.amazon.awssdk.services.dynamodb.model.ScalarAttributeType;
import uk.gov.di.authentication.interventions.api.stub.services.AccountInterventionsDbService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.sharedtest.basetest.DynamoTestConfiguration;

public class AccountInterventionsStubStoreExtension extends DynamoExtension
        implements AfterEachCallback {

    public static final String PAIRWISE_ID_FIELD = "InternalPairwiseId";
    public static final String ACCOUNT_INTERVENTIONS_STORE_TABLE =
            "local-stub-account-interventions";

    private AccountInterventionsDbService db;
    private final ConfigurationService configuration;

    public AccountInterventionsStubStoreExtension() {
        createInstance();
        createTables();
        this.configuration = new DynamoTestConfiguration(REGION, ENVIRONMENT, LOCALSTACK_ENDPOINT);
    }

    @Override
    public void beforeAll(ExtensionContext context) throws Exception {
        super.beforeAll(context);

        db = new AccountInterventionsDbService(configuration);
    }

    @Override
    public void afterEach(ExtensionContext context) throws Exception {
        clearDynamoTable(dynamoDB, ACCOUNT_INTERVENTIONS_STORE_TABLE, PAIRWISE_ID_FIELD);
    }

    @Override
    protected void createTables() {
        if (!tableExists(ACCOUNT_INTERVENTIONS_STORE_TABLE)) {
            createAccountInterventionsStoreTable();
        }
    }

    public void addAccountInterventions(
            String internalPairwiseId,
            boolean blocked,
            boolean suspended,
            boolean reproveIdentity,
            boolean resetPassword) {
        db.addAccountInterventions(
                internalPairwiseId, blocked, suspended, reproveIdentity, resetPassword);
    }

    private void createAccountInterventionsStoreTable() {
        CreateTableRequest request =
                CreateTableRequest.builder()
                        .tableName(ACCOUNT_INTERVENTIONS_STORE_TABLE)
                        .keySchema(
                                KeySchemaElement.builder()
                                        .keyType(KeyType.HASH)
                                        .attributeName(PAIRWISE_ID_FIELD)
                                        .build())
                        .billingMode(BillingMode.PAY_PER_REQUEST)
                        .attributeDefinitions(
                                AttributeDefinition.builder()
                                        .attributeName(PAIRWISE_ID_FIELD)
                                        .attributeType(ScalarAttributeType.S)
                                        .build())
                        .build();

        dynamoDB.createTable(request);
    }
}
