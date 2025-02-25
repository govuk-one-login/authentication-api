package uk.gov.di.orchestration.sharedtest.extensions;

import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import software.amazon.awssdk.services.dynamodb.model.AttributeDefinition;
import software.amazon.awssdk.services.dynamodb.model.BillingMode;
import software.amazon.awssdk.services.dynamodb.model.CreateTableRequest;
import software.amazon.awssdk.services.dynamodb.model.KeySchemaElement;
import software.amazon.awssdk.services.dynamodb.model.KeyType;
import software.amazon.awssdk.services.dynamodb.model.ScalarAttributeType;
import uk.gov.di.orchestration.shared.entity.AuthIdentityCredentials;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.DynamoIdentityService;
import uk.gov.di.orchestration.sharedtest.basetest.DynamoTestConfiguration;

import java.util.Map;
import java.util.Optional;

public class IdentityStoreExtension extends DynamoExtension implements AfterEachCallback {

    public static final String SUBJECT_ID_FIELD = "SubjectID";
    public static final String AUTH_IDENTITY_CREDENTIALS_TABLE = "local-identity-credentials";

    public static final String CLIENT_SESSION_ID_FIELD = "ClientSessionId";
    public static final String ORCH_IDENTITY_CREDENTIALS_TABLE = "local-Orch-Identity-Credentials";

    private DynamoIdentityService dynamoService;
    private final ConfigurationService configuration;

    public IdentityStoreExtension(long ttl) {
        createInstance();
        this.configuration =
                new DynamoTestConfiguration(REGION, ENVIRONMENT, DYNAMO_ENDPOINT) {
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
        clearDynamoTable(dynamoDB, AUTH_IDENTITY_CREDENTIALS_TABLE, SUBJECT_ID_FIELD);
        clearDynamoTable(dynamoDB, ORCH_IDENTITY_CREDENTIALS_TABLE, CLIENT_SESSION_ID_FIELD);
    }

    @Override
    protected void createTables() {
        if (!tableExists(AUTH_IDENTITY_CREDENTIALS_TABLE)) {
            createAuthIdentityCredentialTable();
        }
        if (!tableExists(ORCH_IDENTITY_CREDENTIALS_TABLE)) {
            createIdentityCredentialTable();
        }
    }

    public void addCoreIdentityJWT(String subjectID, String coreIdentityJWT) {
        dynamoService.addCoreIdentityJWT(subjectID, coreIdentityJWT);
    }

    public void saveIdentityClaims(
            String clientSessionId,
            String subjectID,
            Map<String, String> additionalClaims,
            String ipvVot,
            String ipvCoreIdentity) {
        dynamoService.saveIdentityClaims(
                clientSessionId, subjectID, additionalClaims, ipvVot, ipvCoreIdentity);
    }

    public Optional<AuthIdentityCredentials> getIdentityCredentials(String subjectID) {
        return dynamoService.getIdentityCredentials(subjectID);
    }

    private void createAuthIdentityCredentialTable() {
        CreateTableRequest request =
                CreateTableRequest.builder()
                        .tableName(AUTH_IDENTITY_CREDENTIALS_TABLE)
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

    private void createIdentityCredentialTable() {
        CreateTableRequest request =
                CreateTableRequest.builder()
                        .tableName(ORCH_IDENTITY_CREDENTIALS_TABLE)
                        .keySchema(
                                KeySchemaElement.builder()
                                        .keyType(KeyType.HASH)
                                        .attributeName(CLIENT_SESSION_ID_FIELD)
                                        .build())
                        .billingMode(BillingMode.PAY_PER_REQUEST)
                        .attributeDefinitions(
                                AttributeDefinition.builder()
                                        .attributeName(CLIENT_SESSION_ID_FIELD)
                                        .attributeType(ScalarAttributeType.S)
                                        .build())
                        .build();

        dynamoDB.createTable(request);
    }
}
