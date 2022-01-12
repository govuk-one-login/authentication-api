package uk.gov.di.authentication.shared.services;

import com.amazonaws.client.builder.AwsClientBuilder;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDBClientBuilder;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBMapper;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBMapperConfig;
import com.nimbusds.oauth2.sdk.id.ClientID;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.UpdateClientConfigRequest;
import uk.gov.di.authentication.shared.helpers.IdGenerator;

import java.util.List;
import java.util.Optional;

public class DynamoClientService implements ClientService {

    private static final String CLIENT_REGISTRY_TABLE = "client-registry";
    private final DynamoDBMapper clientRegistryMapper;
    private final AmazonDynamoDB dynamoDB;

    public DynamoClientService(String region, String environment, Optional<String> dynamoEndpoint) {
        String tableName = environment + "-" + CLIENT_REGISTRY_TABLE;
        dynamoDB =
                dynamoEndpoint
                        .map(
                                t ->
                                        AmazonDynamoDBClientBuilder.standard()
                                                .withEndpointConfiguration(
                                                        new AwsClientBuilder.EndpointConfiguration(
                                                                t, region)))
                        .orElse(AmazonDynamoDBClientBuilder.standard().withRegion(region))
                        .build();

        DynamoDBMapperConfig clientRegistryConfig =
                new DynamoDBMapperConfig.Builder()
                        .withTableNameOverride(
                                DynamoDBMapperConfig.TableNameOverride.withTableNameReplacement(
                                        tableName))
                        .build();

        this.clientRegistryMapper = new DynamoDBMapper(dynamoDB, clientRegistryConfig);
        warmUp(tableName);
    }

    @Override
    public boolean isValidClient(String clientId) {
        return clientRegistryMapper.load(ClientRegistry.class, clientId) != null;
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
            String serviceType,
            String sectorIdentifierUri,
            String subjectType,
            boolean consentRequired) {
        ClientRegistry clientRegistry =
                new ClientRegistry()
                        .setClientID(clientID)
                        .setClientName(clientName)
                        .setRedirectUrls(redirectUris)
                        .setContacts(contacts)
                        .setScopes(scopes)
                        .setPublicKey(publicKey)
                        .setPostLogoutRedirectUrls(postLogoutRedirectUris)
                        .setServiceType(serviceType)
                        .setSectorIdentifierUri(sectorIdentifierUri)
                        .setSubjectType(subjectType)
                        .setConsentRequired(consentRequired);
        clientRegistryMapper.save(clientRegistry);
    }

    @Override
    public ClientRegistry updateClient(String clientId, UpdateClientConfigRequest updateRequest) {
        ClientRegistry clientRegistry = clientRegistryMapper.load(ClientRegistry.class, clientId);
        Optional.ofNullable(updateRequest.getRedirectUris())
                .ifPresent(clientRegistry::setRedirectUrls);
        Optional.ofNullable(updateRequest.getClientName()).ifPresent(clientRegistry::setClientName);
        Optional.ofNullable(updateRequest.getContacts()).ifPresent(clientRegistry::setContacts);
        Optional.ofNullable(updateRequest.getScopes()).ifPresent(clientRegistry::setScopes);
        Optional.ofNullable(updateRequest.getPostLogoutRedirectUris())
                .ifPresent(clientRegistry::setPostLogoutRedirectUrls);
        Optional.ofNullable(updateRequest.getPublicKey()).ifPresent(clientRegistry::setPublicKey);
        Optional.ofNullable(updateRequest.getServiceType())
                .ifPresent(clientRegistry::setServiceType);
        clientRegistryMapper.save(clientRegistry);
        return clientRegistry;
    }

    @Override
    public Optional<ClientRegistry> getClient(String clientId) {
        return Optional.ofNullable(clientRegistryMapper.load(ClientRegistry.class, clientId));
    }

    @Override
    public ClientID generateClientID() {
        return new ClientID(IdGenerator.generate());
    }

    private void warmUp(String tableName) {
        dynamoDB.describeTable(tableName);
    }
}
