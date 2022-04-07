package uk.gov.di.authentication.sharedtest.extensions;

import com.amazonaws.services.dynamodbv2.model.AttributeDefinition;
import com.amazonaws.services.dynamodbv2.model.BillingMode;
import com.amazonaws.services.dynamodbv2.model.CreateTableRequest;
import com.amazonaws.services.dynamodbv2.model.GlobalSecondaryIndex;
import com.amazonaws.services.dynamodbv2.model.KeySchemaElement;
import com.amazonaws.services.dynamodbv2.model.Projection;
import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import uk.gov.di.authentication.shared.services.DynamoClientService;

import java.util.Collections;
import java.util.List;
import java.util.Optional;

import static com.amazonaws.services.dynamodbv2.model.KeyType.HASH;
import static com.amazonaws.services.dynamodbv2.model.ProjectionType.ALL;
import static com.amazonaws.services.dynamodbv2.model.ScalarAttributeType.S;

public class ClientStoreExtension extends DynamoExtension implements AfterEachCallback {

    public static final String CLIENT_REGISTRY_TABLE = "local-client-registry";
    public static final String CLIENT_ID_FIELD = "ClientID";
    public static final String CLIENT_NAME_FIELD = "ClientName";
    public static final String CLIENT_NAME_INDEX = "ClientNameIndex";

    private DynamoClientService dynamoClientService;

    public void registerClient(
            String clientID,
            String clientName,
            List<String> redirectUris,
            List<String> contacts,
            List<String> scopes,
            String publicKey,
            List<String> postLogoutRedirectUris,
            String backChannelLogoutUri,
            String serviceType,
            String sectorIdentifierUri,
            String subjectType,
            boolean consentRequired,
            List<String> requestUris) {
        dynamoClientService.addClient(
                clientID,
                clientName,
                redirectUris,
                contacts,
                scopes,
                publicKey,
                postLogoutRedirectUris,
                backChannelLogoutUri,
                serviceType,
                sectorIdentifierUri,
                subjectType,
                consentRequired,
                requestUris);
    }

    public void registerClient(
            String clientID,
            String clientName,
            List<String> redirectUris,
            List<String> contacts,
            List<String> scopes,
            String publicKey,
            List<String> postLogoutRedirectUris,
            String backChannelLogoutUri,
            String serviceType,
            String sectorIdentifierUri,
            String subjectType,
            boolean consentRequired) {
        dynamoClientService.addClient(
                clientID,
                clientName,
                redirectUris,
                contacts,
                scopes,
                publicKey,
                postLogoutRedirectUris,
                backChannelLogoutUri,
                serviceType,
                sectorIdentifierUri,
                subjectType,
                consentRequired,
                Collections.emptyList(),
                null);
    }

    public boolean clientExists(String clientID) {
        return dynamoClientService.isValidClient(clientID);
    }

    @Override
    public void beforeAll(ExtensionContext context) throws Exception {
        super.beforeAll(context);
        dynamoClientService =
                new DynamoClientService(REGION, ENVIRONMENT, Optional.of(DYNAMO_ENDPOINT));
    }

    @Override
    public void afterEach(ExtensionContext context) throws Exception {
        clearDynamoTable(dynamoDB, CLIENT_REGISTRY_TABLE, CLIENT_ID_FIELD);
    }

    @Override
    protected void createTables() {
        if (!tableExists(CLIENT_REGISTRY_TABLE)) {
            createClientRegistryTable(CLIENT_REGISTRY_TABLE);
        }
    }

    private void createClientRegistryTable(String tableName) {
        CreateTableRequest request =
                new CreateTableRequest()
                        .withTableName(tableName)
                        .withKeySchema(new KeySchemaElement(CLIENT_ID_FIELD, HASH))
                        .withBillingMode(BillingMode.PAY_PER_REQUEST)
                        .withAttributeDefinitions(
                                new AttributeDefinition(CLIENT_ID_FIELD, S),
                                new AttributeDefinition(CLIENT_NAME_FIELD, S))
                        .withGlobalSecondaryIndexes(
                                new GlobalSecondaryIndex()
                                        .withIndexName(CLIENT_NAME_INDEX)
                                        .withKeySchema(
                                                new KeySchemaElement(CLIENT_NAME_FIELD, HASH))
                                        .withProjection(new Projection().withProjectionType(ALL)));
        dynamoDB.createTable(request);
    }
}
