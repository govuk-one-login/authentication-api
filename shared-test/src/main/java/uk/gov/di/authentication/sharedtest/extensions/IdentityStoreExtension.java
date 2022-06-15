package uk.gov.di.authentication.sharedtest.extensions;

import com.amazonaws.services.dynamodbv2.model.AttributeDefinition;
import com.amazonaws.services.dynamodbv2.model.BillingMode;
import com.amazonaws.services.dynamodbv2.model.CreateTableRequest;
import com.amazonaws.services.dynamodbv2.model.KeySchemaElement;
import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import uk.gov.di.authentication.shared.entity.IdentityCredentials;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoIdentityService;
import uk.gov.di.authentication.sharedtest.basetest.DynamoTestConfiguration;

import java.util.Map;
import java.util.Optional;

import static com.amazonaws.services.dynamodbv2.model.KeyType.HASH;
import static com.amazonaws.services.dynamodbv2.model.ScalarAttributeType.S;

public class IdentityStoreExtension extends DynamoExtension implements AfterEachCallback {

    public static final String SUBJECT_ID_FIELD = "SubjectID";
    public static final String IDENTITY_CREDENTIALS_TABLE = "local-identity-credentials";

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

    public void addAdditionalClaims(String subjectID, Map<String, String> additionalClaims) {
        dynamoService.addAdditionalClaims(subjectID, additionalClaims);
    }

    public Optional<IdentityCredentials> getIdentityCredentials(String subjectID) {
        return dynamoService.getIdentityCredentials(subjectID);
    }

    private void createIdentityCredentialTable() {
        CreateTableRequest request =
                new CreateTableRequest()
                        .withTableName(IDENTITY_CREDENTIALS_TABLE)
                        .withKeySchema(new KeySchemaElement(SUBJECT_ID_FIELD, HASH))
                        .withBillingMode(BillingMode.PAY_PER_REQUEST)
                        .withAttributeDefinitions(new AttributeDefinition(SUBJECT_ID_FIELD, S));
        dynamoDB.createTable(request);
    }
}
