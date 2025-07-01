package uk.gov.di.orchestration.sharedtest.extensions;

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
import uk.gov.di.orchestration.shared.entity.Channel;
import uk.gov.di.orchestration.shared.entity.ClientRegistry;
import uk.gov.di.orchestration.shared.entity.ClientType;
import uk.gov.di.orchestration.shared.entity.PublicKeySource;
import uk.gov.di.orchestration.shared.services.DynamoClientService;
import uk.gov.di.orchestration.sharedtest.basetest.DynamoTestConfiguration;

import java.util.List;
import java.util.Optional;

import static java.util.Collections.emptyList;

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
                ClientType.WEB,
                emptyList(),
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
            List<String> claims) {
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
                ClientType.WEB,
                claims,
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
            ClientType clientType,
            boolean jarValidationRequired,
            List<String> clientLoCs) {
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
                clientType,
                emptyList(),
                jarValidationRequired,
                clientLoCs,
                false,
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
            ClientType clientType,
            boolean jarValidationRequired,
            List<String> clientLoCs,
            boolean maxAgeEnabled,
            boolean pkceEnforced) {
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
                clientType,
                emptyList(),
                jarValidationRequired,
                clientLoCs,
                maxAgeEnabled,
                pkceEnforced);
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
            List<String> claims,
            boolean jarValidationRequired) {
        dynamoClientService.addClient(
                clientID,
                clientName,
                redirectUris,
                contacts,
                PublicKeySource.STATIC.getValue(),
                publicKey,
                null,
                scopes,
                postLogoutRedirectUris,
                backChannelLogoutUri,
                serviceType,
                sectorIdentifierUri,
                subjectType,
                jarValidationRequired,
                claims,
                clientType.getValue(),
                false,
                null,
                ClientAuthenticationMethod.PRIVATE_KEY_JWT.getValue(),
                null,
                emptyList(),
                Channel.WEB.getValue(),
                false,
                false,
                null);
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
            List<String> claims,
            boolean jarValidationRequired,
            List<String> clientLoCs,
            boolean maxAgeEnabled,
            boolean pkceEnforced) {
        dynamoClientService.addClient(
                clientID,
                clientName,
                redirectUris,
                contacts,
                PublicKeySource.STATIC.getValue(),
                publicKey,
                null,
                scopes,
                postLogoutRedirectUris,
                backChannelLogoutUri,
                serviceType,
                sectorIdentifierUri,
                subjectType,
                jarValidationRequired,
                claims,
                clientType.getValue(),
                false,
                null,
                ClientAuthenticationMethod.PRIVATE_KEY_JWT.getValue(),
                null,
                clientLoCs,
                Channel.WEB.getValue(),
                maxAgeEnabled,
                pkceEnforced,
                null);
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
            boolean identityVerificationSupported,
            String clientSecret,
            String isTokenSigningAlgorithm,
            String clientAuthMethod) {
        dynamoClientService.addClient(
                clientID,
                clientName,
                redirectUris,
                contacts,
                PublicKeySource.STATIC.getValue(),
                publicKey,
                null,
                scopes,
                postLogoutRedirectUris,
                backChannelLogoutUri,
                serviceType,
                sectorIdentifierUri,
                subjectType,
                false,
                emptyList(),
                clientType.getValue(),
                identityVerificationSupported,
                clientSecret,
                clientAuthMethod,
                isTokenSigningAlgorithm,
                emptyList(),
                Channel.WEB.getValue(),
                false,
                false,
                null);
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
            String isTokenSigningAlgorithm,
            boolean identityVerificationSupported) {
        dynamoClientService.addClient(
                clientID,
                clientName,
                redirectUris,
                contacts,
                PublicKeySource.STATIC.getValue(),
                publicKey,
                null,
                scopes,
                postLogoutRedirectUris,
                backChannelLogoutUri,
                serviceType,
                sectorIdentifierUri,
                subjectType,
                false,
                emptyList(),
                clientType.getValue(),
                identityVerificationSupported,
                null,
                ClientAuthenticationMethod.PRIVATE_KEY_JWT.getValue(),
                isTokenSigningAlgorithm,
                emptyList(),
                Channel.WEB.getValue(),
                false,
                false,
                null);
    }

    public boolean clientExists(String clientID) {
        return dynamoClientService.isValidClient(clientID);
    }

    public Optional<ClientRegistry> getClient(String clientId) {
        return dynamoClientService.getClient(clientId);
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
