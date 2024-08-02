package uk.gov.di.authentication.sharedtest.extensions;

import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import software.amazon.awssdk.services.dynamodb.model.AttributeDefinition;
import software.amazon.awssdk.services.dynamodb.model.BillingMode;
import software.amazon.awssdk.services.dynamodb.model.CreateTableRequest;
import software.amazon.awssdk.services.dynamodb.model.KeySchemaElement;
import software.amazon.awssdk.services.dynamodb.model.KeyType;
import software.amazon.awssdk.services.dynamodb.model.ScalarAttributeType;
import uk.gov.di.authentication.shared.entity.token.AccessTokenStore;
import uk.gov.di.authentication.shared.services.AccessTokenService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.sharedtest.basetest.DynamoTestConfiguration;

import java.util.List;
import java.util.Optional;

public class AccessTokenStoreExtension extends DynamoExtension implements AfterEachCallback {

    public static final String ACCESS_TOKEN_FIELD = "AccessToken";
    public static final String ACCESS_TOKEN_STORE_TABLE = "local-access-token-store";

    private AccessTokenService dynamoService;
    private final ConfigurationService configuration;

    public AccessTokenStoreExtension(long ttl) {
        createInstance();
        this.configuration =
                new DynamoTestConfiguration(REGION, ENVIRONMENT, LOCALSTACK_ENDPOINT) {
                    @Override
                    public long getAccessTokenExpiry() {
                        return ttl;
                    }
                };
        dynamoService = new AccessTokenService(configuration);
    }

    @Override
    public void beforeAll(ExtensionContext context) throws Exception {
        super.beforeAll(context);

        dynamoService = new AccessTokenService(configuration);
    }

    @Override
    public void afterEach(ExtensionContext context) throws Exception {
        clearDynamoTable(dynamoDB, ACCESS_TOKEN_STORE_TABLE, ACCESS_TOKEN_FIELD);
    }

    @Override
    protected void createTables() {
        if (!tableExists(ACCESS_TOKEN_STORE_TABLE)) {
            createAccessTokenStoreTable();
        }
    }

    public void addAccessTokenStore(
            String accessToken,
            String subjectID,
            List<String> claims,
            boolean isNewAccount,
            String sectorIdentifier,
            Long passwordResetTime) {
        dynamoService.addAccessTokenStore(
                accessToken, subjectID, claims, isNewAccount, sectorIdentifier, passwordResetTime);
    }

    public void addAccessTokenStore(String accessToken, String subjectID, List<String> claims) {
        this.addAccessTokenStore(accessToken, subjectID, claims, false, "any", null);
    }

    public void addAccessTokenStore(String accessToken, Long passwordResetTime) {
        this.addAccessTokenStore(
                accessToken, "subjectId", List.of(), false, "any", passwordResetTime);
    }

    public void setAccessTokenStoreUsed(String accessToken, boolean used) {
        dynamoService.setAccessTokenStoreUsed(accessToken, used);
    }

    public Optional<AccessTokenStore> getAccessToken(String accessToken) {
        return dynamoService.getAccessTokenStore(accessToken);
    }

    private void createAccessTokenStoreTable() {
        CreateTableRequest request =
                CreateTableRequest.builder()
                        .tableName(ACCESS_TOKEN_STORE_TABLE)
                        .keySchema(
                                KeySchemaElement.builder()
                                        .keyType(KeyType.HASH)
                                        .attributeName(ACCESS_TOKEN_FIELD)
                                        .build())
                        .billingMode(BillingMode.PAY_PER_REQUEST)
                        .attributeDefinitions(
                                AttributeDefinition.builder()
                                        .attributeName(ACCESS_TOKEN_FIELD)
                                        .attributeType(ScalarAttributeType.S)
                                        .build())
                        .build();

        dynamoDB.createTable(request);
    }

    public void setAccessTokenTtlToZero(String accessToken) {
        dynamoService.setAccessTokenTtlTestOnly(accessToken, 0L);
    }
}
