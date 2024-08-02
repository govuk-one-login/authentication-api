package uk.gov.di.orchestration.sharedtest.extensions;

import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import software.amazon.awssdk.services.dynamodb.model.AttributeDefinition;
import software.amazon.awssdk.services.dynamodb.model.BillingMode;
import software.amazon.awssdk.services.dynamodb.model.CreateTableRequest;
import software.amazon.awssdk.services.dynamodb.model.KeySchemaElement;
import software.amazon.awssdk.services.dynamodb.model.KeyType;
import software.amazon.awssdk.services.dynamodb.model.ScalarAttributeType;
import uk.gov.di.orchestration.shared.entity.IdentityCredentials;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.DynamoIdentityService;
import uk.gov.di.orchestration.sharedtest.basetest.DynamoTestConfiguration;

import java.util.Map;
import java.util.Optional;

public class IdentityStoreExtension extends DynamoExtension implements AfterEachCallback {

    public static final String SUBJECT_ID_FIELD = "SubjectID";
    public static final String IDENTITY_CREDENTIALS_TABLE = "local-identity-credentials";

    private DynamoIdentityService dynamoService;
    private final ConfigurationService configuration;

    public IdentityStoreExtension(long ttl) {
        createInstance();
        this.configuration =
                new DynamoTestConfiguration(REGION, ENVIRONMENT, LOCALSTACK_ENDPOINT) {
                    @Override
                    public long getAccessTokenExpiry() {
                        return ttl;
                    }
                };
        dynamoService = new DynamoIdentityService(configuration);
    }

    @Override
    public void beforeAll(ExtensionContext context) throws Exception {
        super.beforeAll(context);

        dynamoService = new DynamoIdentityService(configuration);
    }

    @Override
    public void afterEach(ExtensionContext context) throws Exception {
        clearDynamoTable(dynamoDB, IDENTITY_CREDENTIALS_TABLE, SUBJECT_ID_FIELD);
    }

    @Override
    protected void createTables() {
        if (!tableExists(IDENTITY_CREDENTIALS_TABLE)) {
            createIdentityCredentialTable();
        }
    }

    public void addCoreIdentityJWT(String subjectID, String coreIdentityJWT) {
        dynamoService.addCoreIdentityJWT(subjectID, coreIdentityJWT);
    }

    public void saveIdentityClaims(
            String subjectID,
            Map<String, String> additionalClaims,
            String ipvVot,
            String ipvCoreIdentity) {
        dynamoService.saveIdentityClaims(subjectID, additionalClaims, ipvVot, ipvCoreIdentity);
    }

    public Optional<IdentityCredentials> getIdentityCredentials(String subjectID) {
        return dynamoService.getIdentityCredentials(subjectID);
    }

    private void createIdentityCredentialTable() {
        CreateTableRequest request =
                CreateTableRequest.builder()
                        .tableName(IDENTITY_CREDENTIALS_TABLE)
                        .keySchema(
                                KeySchemaElement.builder()
                                        .keyType(KeyType.HASH)
                                        .attributeName(SUBJECT_ID_FIELD)
                                        .build())
                        .billingMode(BillingMode.PAY_PER_REQUEST)
                        .attributeDefinitions(
                                AttributeDefinition.builder()
                                        .attributeName(SUBJECT_ID_FIELD)
                                        .attributeType(ScalarAttributeType.S)
                                        .build())
                        .build();

        dynamoDB.createTable(request);
    }
}
