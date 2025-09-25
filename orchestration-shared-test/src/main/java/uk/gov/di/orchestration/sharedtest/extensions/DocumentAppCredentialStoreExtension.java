package uk.gov.di.orchestration.sharedtest.extensions;

import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import uk.gov.di.authentication.app.entity.DocAppCredential;
import uk.gov.di.authentication.app.services.DynamoDocAppCriService;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.sharedtest.basetest.DynamoTestConfiguration;

import java.util.List;
import java.util.Optional;

public class DocumentAppCredentialStoreExtension extends DynamoExtension
        implements AfterEachCallback {

    public static final String DOC_APP_CREDENTIAL_TABLE = "local-Orch-Doc-App-Credential";
    public static final String SUBJECT_ID_FIELD = "SubjectID";

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
        dynamoDocAppCriService = new DynamoDocAppCriService(configuration);
    }

    @Override
    public void beforeAll(ExtensionContext context) throws Exception {
        super.beforeAll(context);

        dynamoDocAppCriService = new DynamoDocAppCriService(configuration);
    }

    @Override
    public void afterEach(ExtensionContext context) throws Exception {
        clearDynamoTable(dynamoDB, DOC_APP_CREDENTIAL_TABLE, SUBJECT_ID_FIELD);
    }

    @Override
    protected void createTables() {
        if (!tableExists(DOC_APP_CREDENTIAL_TABLE)) {
            createTableWithPartitionKey(DOC_APP_CREDENTIAL_TABLE, SUBJECT_ID_FIELD);
        }
    }

    public void addCredential(String subjectId, List<String> credentials) {
        dynamoDocAppCriService.addDocAppCredential(subjectId, credentials);
    }

    public Optional<DocAppCredential> getOrchCredential(String subjectId) {
        return dynamoDocAppCriService.getDocAppCredential(subjectId);
    }
}
