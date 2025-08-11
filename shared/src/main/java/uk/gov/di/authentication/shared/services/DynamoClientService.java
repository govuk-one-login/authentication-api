package uk.gov.di.authentication.shared.services;

import com.nimbusds.oauth2.sdk.id.ClientID;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbEnhancedClient;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.enhanced.dynamodb.Key;
import software.amazon.awssdk.enhanced.dynamodb.TableSchema;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.UpdateClientConfigRequest;
import uk.gov.di.authentication.shared.helpers.Argon2EncoderHelper;
import uk.gov.di.authentication.shared.helpers.IdGenerator;
import uk.gov.di.authentication.shared.helpers.TableNameHelper;

import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Predicate;

import static uk.gov.di.authentication.shared.dynamodb.DynamoClientHelper.createDynamoEnhancedClient;
import static uk.gov.di.authentication.shared.dynamodb.DynamoClientHelper.warmUp;
import static uk.gov.di.authentication.shared.helpers.TestClientHelper.emailMatchesAllowlist;

public class DynamoClientService implements ClientService {

    private static final String CLIENT_REGISTRY_TABLE = "client-registry";
    private final DynamoDbTable<ClientRegistry> dynamoClientRegistryTable;

    public DynamoClientService(ConfigurationService configurationService) {
        String tableName =
                TableNameHelper.getFullTableName(CLIENT_REGISTRY_TABLE, configurationService);
        var dynamoDBEnhanced = createDynamoEnhancedClient(configurationService);
        this.dynamoClientRegistryTable =
                dynamoDBEnhanced.table(tableName, TableSchema.fromBean(ClientRegistry.class));
        warmUp(dynamoClientRegistryTable);
    }

    public DynamoClientService(
            ConfigurationService configurationService,
            DynamoDbEnhancedClient dynamoDbEnhancedClient) {
        String tableName =
                TableNameHelper.getFullTableName(CLIENT_REGISTRY_TABLE, configurationService);
        this.dynamoClientRegistryTable =
                dynamoDbEnhancedClient.table(tableName, TableSchema.fromBean(ClientRegistry.class));
    }

    @Override
    public boolean isValidClient(String clientId) {
        return dynamoClientRegistryTable.getItem(Key.builder().partitionValue(clientId).build())
                != null;
    }

    @Override
    public void addClient(
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
            List<String> claims,
            String clientType,
            boolean identityVerificationSupported,
            String clientSecret,
            String tokenAuthMethod) {
        var clientRegistry =
                new ClientRegistry()
                        .withClientID(clientID)
                        .withClientName(clientName)
                        .withRedirectUrls(redirectUris)
                        .withContacts(contacts)
                        .withScopes(scopes)
                        .withPublicKey(publicKey)
                        .withPostLogoutRedirectUrls(postLogoutRedirectUris)
                        .withBackChannelLogoutUri(backChannelLogoutUri)
                        .withServiceType(serviceType)
                        .withSectorIdentifierUri(sectorIdentifierUri)
                        .withSubjectType(subjectType)
                        .withClaims(claims)
                        .withClientType(clientType)
                        .withIdentityVerificationSupported(identityVerificationSupported)
                        .withTokenAuthMethod(tokenAuthMethod);
        if (Objects.nonNull(clientSecret)) {
            clientRegistry.withClientSecret(Argon2EncoderHelper.argon2Hash(clientSecret));
        }
        dynamoClientRegistryTable.putItem(clientRegistry);
    }

    @Override
    public ClientRegistry updateClient(String clientId, UpdateClientConfigRequest updateRequest) {
        ClientRegistry clientRegistry =
                dynamoClientRegistryTable.getItem(Key.builder().partitionValue(clientId).build());
        Optional.ofNullable(updateRequest.getRedirectUris())
                .ifPresent(clientRegistry::withRedirectUrls);
        Optional.ofNullable(updateRequest.getClientName())
                .ifPresent(clientRegistry::withClientName);
        Optional.ofNullable(updateRequest.getContacts()).ifPresent(clientRegistry::withContacts);
        Optional.ofNullable(updateRequest.getScopes()).ifPresent(clientRegistry::withScopes);
        Optional.ofNullable(updateRequest.getPostLogoutRedirectUris())
                .ifPresent(clientRegistry::withPostLogoutRedirectUrls);
        Optional.ofNullable(updateRequest.getPublicKey()).ifPresent(clientRegistry::withPublicKey);
        Optional.ofNullable(updateRequest.getServiceType())
                .ifPresent(clientRegistry::withServiceType);
        Optional.ofNullable(updateRequest.getSectorIdentifierUri())
                .ifPresent(clientRegistry::withSectorIdentifierUri);
        Optional.ofNullable(updateRequest.getClaims()).ifPresent(clientRegistry::withClaims);
        dynamoClientRegistryTable.putItem(clientRegistry);
        return clientRegistry;
    }

    @Override
    public Optional<ClientRegistry> getClient(String clientId) {
        return Optional.ofNullable(
                dynamoClientRegistryTable.getItem(Key.builder().partitionValue(clientId).build()));
    }

    @Override
    public ClientID generateClientID() {
        return new ClientID(IdGenerator.generate());
    }

    @Override
    public boolean isTestJourney(String clientID, String emailAddress) {
        var client = getClient(clientID);

        return client.map(ClientRegistry::getTestClientEmailAllowlist)
                .filter(Predicate.not(List::isEmpty))
                .map(list -> emailMatchesAllowlist(emailAddress, list))
                .orElse(false);
    }
}
