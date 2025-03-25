package uk.gov.di.authentication.sharedtest.extensions;

import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import software.amazon.awssdk.services.dynamodb.model.AttributeDefinition;
import software.amazon.awssdk.services.dynamodb.model.BillingMode;
import software.amazon.awssdk.services.dynamodb.model.CreateTableRequest;
import software.amazon.awssdk.services.dynamodb.model.KeySchemaElement;
import software.amazon.awssdk.services.dynamodb.model.KeyType;
import software.amazon.awssdk.services.dynamodb.model.ScalarAttributeType;
import uk.gov.di.authentication.shared.entity.AuthCodeStore;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoAuthCodeService;
import uk.gov.di.authentication.sharedtest.basetest.DynamoTestConfiguration;

import java.util.List;
import java.util.Optional;

public class AuthCodeExtension extends DynamoExtension implements AfterEachCallback {

    public static final String AUTH_CODE_FIELD = "AuthCode";
    public static final String AUTH_CODE_STORE_TABLE = "local-auth-code-store";

    private DynamoAuthCodeService dynamoAuthCodeService;
    private final ConfigurationService configuration;

    public AuthCodeExtension(long ttl) {
        createInstance();
        this.configuration =
                new DynamoTestConfiguration(REGION, ENVIRONMENT, DYNAMO_ENDPOINT) {
                    @Override
                    public long getAuthCodeExpiry() {
                        return ttl;
                    }
                };
        dynamoAuthCodeService = new DynamoAuthCodeService(configuration);
    }

    @Override
    public void beforeAll(ExtensionContext context) throws Exception {
        super.beforeAll(context);

        dynamoAuthCodeService = new DynamoAuthCodeService(configuration);
    }

    @Override
    public void afterEach(ExtensionContext context) throws Exception {
        clearDynamoTable(dynamoDB, AUTH_CODE_STORE_TABLE, AUTH_CODE_FIELD);
    }

    @Override
    protected void createTables() {
        if (!tableExists(AUTH_CODE_STORE_TABLE)) {
            createAuthCodeStoreTable();
        }
    }

    public Optional<AuthCodeStore> getAuthCode(String authCode) {
        return dynamoAuthCodeService.getAuthCodeStore(authCode);
    }

    public void saveAuthCode(
            String subjectID,
            String authCode,
            List<String> claims,
            boolean hasBeenUsed,
            String sectorIdentifier,
            boolean isNewAccount,
            String journeyId) {

        dynamoAuthCodeService.saveAuthCode(
                subjectID,
                authCode,
                claims,
                hasBeenUsed,
                sectorIdentifier,
                isNewAccount,
                null,
                journeyId);
    }

    private void createAuthCodeStoreTable() {
        CreateTableRequest request =
                CreateTableRequest.builder()
                        .tableName(AUTH_CODE_STORE_TABLE)
                        .keySchema(
                                KeySchemaElement.builder()
                                        .keyType(KeyType.HASH)
                                        .attributeName(AUTH_CODE_FIELD)
                                        .build())
                        .billingMode(BillingMode.PAY_PER_REQUEST)
                        .attributeDefinitions(
                                AttributeDefinition.builder()
                                        .attributeName(AUTH_CODE_FIELD)
                                        .attributeType(ScalarAttributeType.S)
                                        .build())
                        .build();

        dynamoDB.createTable(request);
    }
}
