package uk.gov.di.orchestration.sharedtest.extensions;

import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import software.amazon.awssdk.services.dynamodb.model.AttributeDefinition;
import software.amazon.awssdk.services.dynamodb.model.BillingMode;
import software.amazon.awssdk.services.dynamodb.model.CreateTableRequest;
import software.amazon.awssdk.services.dynamodb.model.GlobalSecondaryIndex;
import software.amazon.awssdk.services.dynamodb.model.KeySchemaElement;
import software.amazon.awssdk.services.dynamodb.model.KeyType;
import software.amazon.awssdk.services.dynamodb.model.Projection;
import software.amazon.awssdk.services.dynamodb.model.ProjectionType;
import software.amazon.awssdk.services.dynamodb.model.ScalarAttributeType;
import uk.gov.di.orchestration.shared.entity.OrchAccessTokenItem;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.OrchAccessTokenService;
import uk.gov.di.orchestration.sharedtest.basetest.DynamoTestConfiguration;

import java.util.Optional;

public class OrchAccessTokenExtension extends DynamoExtension implements AfterEachCallback {

    public static final String TABLE_NAME = "local-Access-Token";
    private static final String CLIENT_ID_FIELD = "ClientId";
    private static final String RP_PAIRWISE_ID_FIELD = "RpPairwiseId";
    private static final String AUTH_CODE_FIELD = "AuthCode";
    private static final String AUTH_CODE_INDEX = "AuthCodeIndex";
    private OrchAccessTokenService orchAccessTokenService;
    private final ConfigurationService configurationService;

    public OrchAccessTokenExtension() {
        this.configurationService =
                new DynamoTestConfiguration(REGION, ENVIRONMENT, DYNAMO_ENDPOINT);
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
                                        .build(),
                                KeySchemaElement.builder()
                                        .keyType(KeyType.RANGE)
                                        .attributeName(RP_PAIRWISE_ID_FIELD)
                                        .build())
                        .billingMode(BillingMode.PAY_PER_REQUEST)
                        .attributeDefinitions(
                                AttributeDefinition.builder()
                                        .attributeName(CLIENT_ID_FIELD)
                                        .attributeType(ScalarAttributeType.S)
                                        .build(),
                                AttributeDefinition.builder()
                                        .attributeName(RP_PAIRWISE_ID_FIELD)
                                        .attributeType(ScalarAttributeType.S)
                                        .build(),
                                AttributeDefinition.builder()
                                        .attributeName(AUTH_CODE_FIELD)
                                        .attributeType(ScalarAttributeType.S)
                                        .build())
                        .globalSecondaryIndexes(
                                GlobalSecondaryIndex.builder()
                                        .indexName(AUTH_CODE_INDEX)
                                        .keySchema(
                                                KeySchemaElement.builder()
                                                        .keyType(KeyType.HASH)
                                                        .attributeName(AUTH_CODE_FIELD)
                                                        .build())
                                        .projection(
                                                Projection.builder()
                                                        .projectionType(ProjectionType.ALL)
                                                        .build())
                                        .build())
                        .build();
        dynamoDB.createTable(request);
    }

    public void saveAccessToken(
            String clientId,
            String rpPairwiseId,
            String token,
            String internalPairwiseSubjectId,
            String clientSessionId,
            String authCode) {
        orchAccessTokenService.saveAccessToken(
                clientId,
                rpPairwiseId,
                token,
                internalPairwiseSubjectId,
                clientSessionId,
                authCode);
    }

    public Optional<OrchAccessTokenItem> getAccessToken(String clientId, String rpPairwiseId) {
        return orchAccessTokenService.getAccessToken(clientId, rpPairwiseId);
    }

    public Optional<OrchAccessTokenItem> getAccessTokenForAuthCode(String authCode) {
        return orchAccessTokenService.getAccessTokenForAuthCode(authCode);
    }
}
