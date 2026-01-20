package uk.gov.di.orchestration.shared.services;

import com.nimbusds.oauth2.sdk.id.ClientID;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbEnhancedClient;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.enhanced.dynamodb.Key;
import software.amazon.awssdk.enhanced.dynamodb.TableSchema;
import uk.gov.di.orchestration.shared.entity.ClientRegistry;
import uk.gov.di.orchestration.shared.entity.ManualUpdateClientRegistryRequest;
import uk.gov.di.orchestration.shared.entity.UpdateClientConfigRequest;
import uk.gov.di.orchestration.shared.helpers.Argon2EncoderHelper;
import uk.gov.di.orchestration.shared.helpers.IdGenerator;

import java.util.List;
import java.util.Objects;
import java.util.Optional;

import static uk.gov.di.orchestration.shared.dynamodb.DynamoClientHelper.createDynamoEnhancedClient;

public class DynamoClientService implements ClientService {

    private static final String CLIENT_REGISTRY_TABLE = "client-registry";
    private final DynamoDbTable<ClientRegistry> dynamoClientRegistryTable;

    public DynamoClientService(ConfigurationService configurationService) {
        var tableName = configurationService.getEnvironment() + "-" + CLIENT_REGISTRY_TABLE;

        // This is for processing identity handler
        if (configurationService.getOrchDynamoArnPrefix().isPresent()) {
            tableName = configurationService.getOrchDynamoArnPrefix().get() + CLIENT_REGISTRY_TABLE;
        }
        var dynamoDBEnhanced = createDynamoEnhancedClient(configurationService);
        this.dynamoClientRegistryTable =
                dynamoDBEnhanced.table(tableName, TableSchema.fromBean(ClientRegistry.class));
    }

    public DynamoClientService(
            ConfigurationService configurationService,
            DynamoDbEnhancedClient dynamoDbEnhancedClient) {
        var tableName = configurationService.getEnvironment() + "-" + CLIENT_REGISTRY_TABLE;
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
            String publicKeySource,
            String publicKey,
            String jwksUrl,
            List<String> scopes,
            List<String> postLogoutRedirectUris,
            String backChannelLogoutUri,
            String serviceType,
            String sectorIdentifierUri,
            String subjectType,
            boolean jarValidationRequired,
            List<String> claims,
            String clientType,
            boolean identityVerificationSupported,
            String clientSecret,
            String tokenAuthMethod,
            String idTokenSigningAlgorithm,
            List<String> clientLoCs,
            String channel,
            boolean maxAgeEnabled,
            boolean pkceEnforced,
            String landingPageUrl) {
        var clientRegistry =
                new ClientRegistry()
                        .withClientID(clientID)
                        .withClientName(clientName)
                        .withRedirectUrls(redirectUris)
                        .withContacts(contacts)
                        .withPublicKeySource(publicKeySource)
                        .withPublicKey(publicKey)
                        .withJwksUrl(jwksUrl)
                        .withScopes(scopes)
                        .withPostLogoutRedirectUrls(postLogoutRedirectUris)
                        .withBackChannelLogoutUri(backChannelLogoutUri)
                        .withServiceType(serviceType)
                        .withSectorIdentifierUri(sectorIdentifierUri)
                        .withSubjectType(subjectType)
                        .withJarValidationRequired(jarValidationRequired)
                        .withClaims(claims)
                        .withClientType(clientType)
                        .withIdentityVerificationSupported(identityVerificationSupported)
                        .withIdTokenSigningAlgorithm(idTokenSigningAlgorithm)
                        .withTokenAuthMethod(tokenAuthMethod)
                        .withActive(true)
                        .withChannel(channel)
                        .withMaxAgeEnabled(maxAgeEnabled)
                        .withPKCEEnforced(pkceEnforced)
                        .withLandingPageUrl(landingPageUrl);
        if (Objects.nonNull(clientSecret)) {
            clientRegistry.withClientSecret(Argon2EncoderHelper.argon2Hash(clientSecret));
        }
        if (Objects.nonNull(clientLoCs)) {
            clientRegistry.withClientLoCs(clientLoCs);
        }
        dynamoClientRegistryTable.putItem(clientRegistry);
    }

    @Override
    public ClientRegistry updateSSEClient(
            String clientId, UpdateClientConfigRequest updateRequest) {
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
        Optional.ofNullable(updateRequest.getPublicKeySource())
                .ifPresent(clientRegistry::withPublicKeySource);
        Optional.ofNullable(updateRequest.getPublicKey()).ifPresent(clientRegistry::withPublicKey);
        Optional.ofNullable(updateRequest.getJwksUrl()).ifPresent(clientRegistry::withJwksUrl);
        Optional.ofNullable(updateRequest.getServiceType())
                .ifPresent(clientRegistry::withServiceType);
        Optional.ofNullable(updateRequest.getClientType())
                .ifPresent(clientRegistry::withClientType);
        Optional.ofNullable(updateRequest.getSectorIdentifierUri())
                .ifPresent(clientRegistry::withSectorIdentifierUri);
        Optional.ofNullable(updateRequest.getJarValidationRequired())
                .ifPresent(clientRegistry::withJarValidationRequired);
        Optional.ofNullable(updateRequest.getClaims()).ifPresent(clientRegistry::withClaims);
        Optional.ofNullable(updateRequest.getClientLoCs())
                .ifPresent(clientRegistry::withClientLoCs);
        Optional.ofNullable(updateRequest.getBackChannelLogoutUri())
                .ifPresent(clientRegistry::withBackChannelLogoutUri);
        Optional.ofNullable(updateRequest.getIdTokenSigningAlgorithm())
                .ifPresent(clientRegistry::withIdTokenSigningAlgorithm);
        Optional.ofNullable(updateRequest.getIdentityVerificationSupported())
                .ifPresent(clientRegistry::withIdentityVerificationSupported);
        Optional.ofNullable(updateRequest.getChannel()).ifPresent(clientRegistry::withChannel);
        Optional.ofNullable(updateRequest.getMaxAgeEnabled())
                .ifPresent(clientRegistry::withMaxAgeEnabled);
        Optional.ofNullable(updateRequest.getPKCEEnforced())
                .ifPresent(clientRegistry::withPKCEEnforced);
        Optional.ofNullable(updateRequest.getLandingPageUrl())
                .ifPresent(clientRegistry::withLandingPageUrl);
        dynamoClientRegistryTable.putItem(clientRegistry);
        return clientRegistry;
    }

    @Override
    public ClientRegistry manualUpdateClient(
            String clientId, ManualUpdateClientRegistryRequest updateRequest) {
        ClientRegistry clientRegistry =
                dynamoClientRegistryTable.getItem(Key.builder().partitionValue(clientId).build());
        Optional.ofNullable(updateRequest.rateLimit())
                .ifPresent(
                        rateLimit ->
                                clientRegistry.withRateLimit(
                                        rateLimit.isBlank() ? null : Integer.parseInt(rateLimit)));
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
}
