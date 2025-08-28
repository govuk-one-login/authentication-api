package uk.gov.di.orchestration.sharedtest.extensions;

import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import software.amazon.awssdk.services.dynamodb.model.AttributeDefinition;
import software.amazon.awssdk.services.dynamodb.model.BillingMode;
import software.amazon.awssdk.services.dynamodb.model.CreateTableRequest;
import software.amazon.awssdk.services.dynamodb.model.KeySchemaElement;
import software.amazon.awssdk.services.dynamodb.model.KeyType;
import software.amazon.awssdk.services.dynamodb.model.ScalarAttributeType;
import uk.gov.di.orchestration.shared.entity.JwksCacheItem;
import uk.gov.di.orchestration.shared.services.JwksCacheService;
import uk.gov.di.orchestration.sharedtest.basetest.DynamoTestConfiguration;

import java.util.List;
import java.util.Optional;

public class JwksCacheExtension extends DynamoExtension implements AfterEachCallback {
    public static final String TABLE_NAME = "local-Jwks-Cache";
    public static final String JWKS_URL_FIELD = "JwksUrl";
    public static final String KEY_ID_FIELD = "KeyId";
    private final JwksCacheService jwksCacheService;

    public JwksCacheExtension() {
        createInstance();
        var configurationService =
                new DynamoTestConfiguration(REGION, ENVIRONMENT, DYNAMO_ENDPOINT);
        jwksCacheService = new JwksCacheService(configurationService);
    }

    @Override
    public void afterEach(ExtensionContext context) throws Exception {
        clearDynamoTable(dynamoDB, TABLE_NAME, JWKS_URL_FIELD, Optional.of(KEY_ID_FIELD));
    }

    @Override
    protected void createTables() {
        if (!tableExists(TABLE_NAME)) {
            createJwksCacheTable();
        }
    }

    private void createJwksCacheTable() {
        CreateTableRequest request =
                CreateTableRequest.builder()
                        .tableName(TABLE_NAME)
                        .attributeDefinitions(
                                AttributeDefinition.builder()
                                        .attributeName(JWKS_URL_FIELD)
                                        .attributeType(ScalarAttributeType.S)
                                        .build(),
                                AttributeDefinition.builder()
                                        .attributeName(KEY_ID_FIELD)
                                        .attributeType(ScalarAttributeType.S)
                                        .build())
                        .keySchema(
                                KeySchemaElement.builder()
                                        .keyType(KeyType.HASH)
                                        .attributeName(JWKS_URL_FIELD)
                                        .build(),
                                KeySchemaElement.builder()
                                        .keyType(KeyType.RANGE)
                                        .attributeName(KEY_ID_FIELD)
                                        .build())
                        .billingMode(BillingMode.PAY_PER_REQUEST)
                        .build();
        dynamoDB.createTable(request);
    }

    public void storeKey(JwksCacheItem item) {
        jwksCacheService.storeKey(item);
    }

    public List<JwksCacheItem> getSigningKeys(String jwksUrl) {
        return jwksCacheService.getSigningKeys(jwksUrl);
    }

    public Optional<JwksCacheItem> getEncryptionKey(String jwksUrl) {
        return jwksCacheService.getEncryptionKey(jwksUrl);
    }
}
