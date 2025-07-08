package uk.gov.di.orchestration.sharedtest.extensions;

import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import software.amazon.awssdk.services.dynamodb.model.AttributeDefinition;
import software.amazon.awssdk.services.dynamodb.model.BillingMode;
import software.amazon.awssdk.services.dynamodb.model.CreateTableRequest;
import software.amazon.awssdk.services.dynamodb.model.KeySchemaElement;
import software.amazon.awssdk.services.dynamodb.model.KeyType;
import software.amazon.awssdk.services.dynamodb.model.ScalarAttributeType;
import uk.gov.di.authentication.app.entity.DocAppCredential;
import uk.gov.di.authentication.app.services.DynamoDocAppCriService;
import uk.gov.di.authentication.app.services.DynamoDocAppService;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.sharedtest.basetest.DynamoTestConfiguration;

import java.util.List;
import java.util.Optional;

public class DocumentAppCredentialStoreExtension extends DynamoExtension
        implements AfterEachCallback {

    public static final String CREDENTIAL_REGISTRY_TABLE = "local-doc-app-credential";
    public static final String DOC_APP_CREDENTIAL_TABLE = "local-Orch-Doc-App-Credential";
    public static final String SUBJECT_ID_FIELD = "SubjectID";

    private DynamoDocAppService dynamoDocAppService;
    private DynamoDocAppCriService dynamoDocAppCriService;
    private final ConfigurationService configuration;

    public DocumentAppCredentialStoreExtension(long ttl) {
        createInstance();
        this.configuration =
                new DynamoTestConfiguration(
                        BaseAwsResourceExtension.REGION,
                        DynamoExtension.ENVIRONMENT,
                        DynamoExtension.DYNAMO_ENDPOINT) {
                    @Override
                    public long getAccessTokenExpiry() {
                        return ttl;
                    }
                };
        dynamoDocAppService = new DynamoDocAppService(configuration);
        dynamoDocAppCriService = new DynamoDocAppCriService(configuration);
    }

    @Override
    public void beforeAll(ExtensionContext context) throws Exception {
        super.beforeAll(context);

        dynamoDocAppService = new DynamoDocAppService(configuration);
        dynamoDocAppCriService = new DynamoDocAppCriService(configuration);
    }

    @Override
    public void afterEach(ExtensionContext context) throws Exception {
        clearDynamoTable(dynamoDB, CREDENTIAL_REGISTRY_TABLE, SUBJECT_ID_FIELD);
        clearDynamoTable(dynamoDB, DOC_APP_CREDENTIAL_TABLE, SUBJECT_ID_FIELD);
    }

    @Override
    protected void createTables() {
        if (!tableExists(CREDENTIAL_REGISTRY_TABLE)) {
            createCredentialRegistryTable(CREDENTIAL_REGISTRY_TABLE);
        }
        if (!tableExists(DOC_APP_CREDENTIAL_TABLE)) {
            createCredentialRegistryTable(DOC_APP_CREDENTIAL_TABLE);
        }
    }

    private void createCredentialRegistryTable(String tableName) {
        CreateTableRequest request =
                CreateTableRequest.builder()
                        .tableName(tableName)
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

    public void addCredential(String subjectId, List<String> credentials) {
        dynamoDocAppService.addDocAppCredential(subjectId, credentials);
    }

    public Optional<DocAppCredential> getCredential(String subjectId) {
        return dynamoDocAppService.getDocAppCredential(subjectId);
    }

    public Optional<DocAppCredential> getOrchCredential(String subjectId) {
        return dynamoDocAppCriService.getDocAppCredential(subjectId);
    }
}
