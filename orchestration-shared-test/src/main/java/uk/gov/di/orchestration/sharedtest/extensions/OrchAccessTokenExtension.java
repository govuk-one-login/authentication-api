package uk.gov.di.orchestration.sharedtest.extensions;

import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import software.amazon.awssdk.services.dynamodb.model.AttributeDefinition;
import software.amazon.awssdk.services.dynamodb.model.BillingMode;
import software.amazon.awssdk.services.dynamodb.model.CreateTableRequest;
import software.amazon.awssdk.services.dynamodb.model.KeySchemaElement;
import software.amazon.awssdk.services.dynamodb.model.KeyType;
import software.amazon.awssdk.services.dynamodb.model.ScalarAttributeType;
import uk.gov.di.orchestration.shared.entity.OrchAccessTokenItem;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.OrchAccessTokenService;
import uk.gov.di.orchestration.sharedtest.basetest.DynamoTestConfiguration;

import java.util.Optional;

public class OrchAccessTokenExtension extends DynamoExtension implements AfterEachCallback {

    private static final String CLIENT_ID_FIELD = "clientId";
    private static final String RP_PAIRWISE_ID_FIELD = "rpPairwiseId";
    public static final String TABLE_NAME = "local-access-token";
    private OrchAccessTokenService orchAccessTokenService;
    private final ConfigurationService configurationService;

    public OrchAccessTokenExtension() {
        createInstance();
        this.configurationService =
                new DynamoTestConfiguration(REGION, ENVIRONMENT, DYNAMO_ENDPOINT);
        orchAccessTokenService = new OrchAccessTokenService(configurationService);
    }

    @Override
    public void beforeAll(ExtensionContext context) throws Exception {
        super.beforeAll(context);

        orchAccessTokenService = new OrchAccessTokenService(configurationService);
    }

    @Override
    public void afterEach(ExtensionContext context) throws Exception {
        clearDynamoTable(dynamoDB, TABLE_NAME, CLIENT_ID_FIELD, Optional.of(RP_PAIRWISE_ID_FIELD));
    }

    @Override
    protected void createTables() {
        if (!tableExists(TABLE_NAME)) {
            createOrchAccessTokenTable();
        }
    }

    private void createOrchAccessTokenTable() {
        CreateTableRequest request =
                CreateTableRequest.builder()
                        .tableName(TABLE_NAME)
                        .keySchema(
                                KeySchemaElement.builder()
                                        .keyType(KeyType.HASH)
                                        .attributeName(CLIENT_ID_FIELD)
                                        .build())
                        .billingMode(BillingMode.PAY_PER_REQUEST)
                        .attributeDefinitions(
                                AttributeDefinition.builder()
                                        .attributeName(CLIENT_ID_FIELD)
                                        .attributeType(ScalarAttributeType.S)
                                        .build())
                        .build();
        dynamoDB.createTable(request);
    }

    public void storeAccessToken(OrchAccessTokenItem accessTokenItem) {
        orchAccessTokenService.storeAccessToken(accessTokenItem);
    }

    public Optional<OrchAccessTokenItem> getAccessToken(String clientId, String rpPairwiseId) {
        return orchAccessTokenService.getAccessToken(clientId, rpPairwiseId);
    }
}
