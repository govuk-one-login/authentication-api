package uk.gov.di.authentication.sharedtest.extensions;

import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import software.amazon.awssdk.services.dynamodb.model.AttributeDefinition;
import software.amazon.awssdk.services.dynamodb.model.BillingMode;
import software.amazon.awssdk.services.dynamodb.model.CreateTableRequest;
import software.amazon.awssdk.services.dynamodb.model.GlobalSecondaryIndex;
import software.amazon.awssdk.services.dynamodb.model.KeySchemaElement;
import software.amazon.awssdk.services.dynamodb.model.KeyType;
import software.amazon.awssdk.services.dynamodb.model.ProjectionType;
import software.amazon.awssdk.services.dynamodb.model.ScalarAttributeType;
import uk.gov.di.authentication.shared.entity.ClientType;
import uk.gov.di.authentication.shared.services.DynamoClientService;
import uk.gov.di.authentication.sharedtest.basetest.DynamoTestConfiguration;

import java.util.Collections;
import java.util.List;

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
            String subjectType) {
        registerClient(
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
                false,
                ClientType.WEB);
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
        registerClient(
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
                ClientType.WEB);
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
            boolean consentRequired,
            ClientType clientType) {
        registerClient(
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
                clientType,
                false);
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
            boolean consentRequired,
            ClientType clientType,
            boolean identityVerificationSupported,
            String clientSecret,
            String clientAuthMethod) {
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
                clientType.getValue(),
                identityVerificationSupported,
                clientSecret,
                clientAuthMethod);
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
            ClientType clientType,
            boolean identityVerificationSupported) {
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
                false,
                Collections.emptyList(),
                clientType.getValue(),
                identityVerificationSupported,
                null,
                ClientAuthenticationMethod.PRIVATE_KEY_JWT.getValue());
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
            boolean consentRequired,
            ClientType clientType,
            boolean identityVerificationSupported) {
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
                clientType.getValue(),
                identityVerificationSupported,
                null,
                ClientAuthenticationMethod.PRIVATE_KEY_JWT.getValue());
    }

    public boolean clientExists(String clientID) {
        return dynamoClientService.isValidClient(clientID);
    }

    @Override
    public void beforeAll(ExtensionContext context) throws Exception {
        super.beforeAll(context);
        dynamoClientService =
                new DynamoClientService(
                        new DynamoTestConfiguration(REGION, ENVIRONMENT, DYNAMO_ENDPOINT));
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
                CreateTableRequest.builder()
                        .tableName(tableName)
                        .keySchema(
                                KeySchemaElement.builder()
                                        .keyType(KeyType.HASH)
                                        .attributeName(CLIENT_ID_FIELD)
                                        .build())
                        .billingMode(BillingMode.PAY_PER_REQUEST)
                        .attributeDefinitions(
                                AttributeDefinition.builder()
                                        .attributeName(CLIENT_ID_FIELD)
                                        .attributeType(ScalarAttributeType.S)
                                        .build(),
                                AttributeDefinition.builder()
                                        .attributeName(CLIENT_NAME_FIELD)
                                        .attributeType(ScalarAttributeType.S)
                                        .build())
                        .globalSecondaryIndexes(
                                GlobalSecondaryIndex.builder()
                                        .indexName(CLIENT_NAME_INDEX)
                                        .keySchema(
                                                KeySchemaElement.builder()
                                                        .attributeName(CLIENT_NAME_FIELD)
                                                        .keyType(KeyType.HASH)
                                                        .build())
                                        .projection(t -> t.projectionType(ProjectionType.ALL))
                                        .build())
                        .build();
        dynamoDB.createTable(request);
    }
}
