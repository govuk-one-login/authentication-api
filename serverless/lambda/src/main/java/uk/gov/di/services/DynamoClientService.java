package uk.gov.di.services;

import com.amazonaws.client.builder.AwsClientBuilder;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDBClientBuilder;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBMapper;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBMapperConfig;
import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.OIDCError;
import uk.gov.di.entity.ClientRegistry;
import uk.gov.di.helpers.IdGenerator;

import java.util.List;
import java.util.Optional;

public class DynamoClientService implements ClientService {

    private static final String CLIENT_REGISTRY_TABLE = "client-registry";
    private final DynamoDBMapper clientRegistryMapper;

    public DynamoClientService(String region, String environment, Optional<String> dynamoEndpoint) {
        AmazonDynamoDB dynamoDB =
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
                                        environment + "-" + CLIENT_REGISTRY_TABLE))
                        .build();

        this.clientRegistryMapper = new DynamoDBMapper(dynamoDB, clientRegistryConfig);
    }

    @Override
    public Optional<ErrorObject> getErrorForAuthorizationRequest(AuthorizationRequest authRequest) {
        if (!isValidClient(authRequest.getClientID().toString())) {
            return Optional.of(OIDCError.UNMET_AUTHENTICATION_REQUIREMENTS);
        }
        return Optional.empty();
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
            List<String> postLogoutRedirectUris) {
        ClientRegistry clientRegistry =
                new ClientRegistry()
                        .setClientID(clientID)
                        .setClientName(clientName)
                        .setRedirectUrls(redirectUris)
                        .setContacts(contacts)
                        .setScopes(scopes)
                        .setPublicKey(publicKey)
                        .setPostLogoutRedirectUrls(postLogoutRedirectUris);
        clientRegistryMapper.save(clientRegistry);
    }

    @Override
    public Optional<ClientRegistry> getClient(String clientId) {
        return Optional.ofNullable(clientRegistryMapper.load(ClientRegistry.class, clientId));
    }

    @Override
    public ClientID generateClientID() {
        return new ClientID(IdGenerator.generate());
    }
}
