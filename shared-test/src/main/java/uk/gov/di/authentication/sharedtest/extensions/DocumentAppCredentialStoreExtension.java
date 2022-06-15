package uk.gov.di.authentication.sharedtest.extensions;

import com.amazonaws.services.dynamodbv2.model.AttributeDefinition;
import com.amazonaws.services.dynamodbv2.model.BillingMode;
import com.amazonaws.services.dynamodbv2.model.CreateTableRequest;
import com.amazonaws.services.dynamodbv2.model.KeySchemaElement;
import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import uk.gov.di.authentication.app.entity.DocAppCredential;
import uk.gov.di.authentication.app.services.DynamoDocAppService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.sharedtest.basetest.DynamoTestConfiguration;

import java.util.Optional;

import static com.amazonaws.services.dynamodbv2.model.KeyType.HASH;
import static com.amazonaws.services.dynamodbv2.model.ScalarAttributeType.S;

public class DocumentAppCredentialStoreExtension extends DynamoExtension
        implements AfterEachCallback {

    public static final String CREDENTIAL_REGISTRY_TABLE = "local-doc-app-credential";
    public static final String SUBJECT_ID_FIELD = "SubjectID";

    private DynamoDocAppService dynamoDocAppService;
    private final ConfigurationService configuration;

    public DocumentAppCredentialStoreExtension(long ttl) {
        createInstance();
        this.configuration =
                new DynamoTestConfiguration(REGION, ENVIRONMENT, DYNAMO_ENDPOINT) {
                    @Override
                    public long getAccessTokenExpiry() {
                        return ttl;
                    }
                };
        dynamoDocAppService = new DynamoDocAppService(configuration);
    }

    @Override
    public void beforeAll(ExtensionContext context) throws Exception {
        super.beforeAll(context);

        dynamoDocAppService = new DynamoDocAppService(configuration);
    }

    @Override
    public void afterEach(ExtensionContext context) throws Exception {
        clearDynamoTable(dynamoDB, CREDENTIAL_REGISTRY_TABLE, SUBJECT_ID_FIELD);
    }

    @Override
    protected void createTables() {
        if (!tableExists(CREDENTIAL_REGISTRY_TABLE)) {
            createCredentialRegistryTable(CREDENTIAL_REGISTRY_TABLE);
        }
    }

    private void createCredentialRegistryTable(String tableName) {
        CreateTableRequest request =
                new CreateTableRequest()
                        .withTableName(tableName)
                        .withKeySchema(new KeySchemaElement(SUBJECT_ID_FIELD, HASH))
                        .withBillingMode(BillingMode.PAY_PER_REQUEST)
                        .withAttributeDefinitions(new AttributeDefinition(SUBJECT_ID_FIELD, S));
        dynamoDB.createTable(request);
    }

    public void addCredential(String subjectId, String credential) {
        dynamoDocAppService.addDocAppCredential(subjectId, credential);
    }

    public Optional<DocAppCredential> getCredential(String subjectId) {
        return dynamoDocAppService.getDocAppCredential(subjectId);
    }
}
