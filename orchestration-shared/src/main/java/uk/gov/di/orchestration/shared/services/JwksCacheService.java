package uk.gov.di.orchestration.shared.services;

import com.nimbusds.jose.jwk.KeyUse;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import uk.gov.di.orchestration.shared.entity.JwksCacheItem;

import java.util.List;
import java.util.Optional;

public class JwksCacheService extends BaseDynamoService<JwksCacheItem> {
    public JwksCacheService(ConfigurationService configurationService) {
        super(JwksCacheItem.class, "Jwks-Cache", configurationService, true);
    }

    public JwksCacheService(
            DynamoDbClient dynamoDbClient,
            DynamoDbTable<JwksCacheItem> dynamoDbTable,
            ConfigurationService configurationService) {
        super(dynamoDbTable, dynamoDbClient, configurationService);
    }

    public void storeKey(JwksCacheItem jwksCacheItem) {
        put(jwksCacheItem);
    }

    public List<JwksCacheItem> getSigningKeys(String jwksUrl) {
        return queryTableStream(jwksUrl)
                .filter(
                        jwksCacheItem ->
                                KeyUse.SIGNATURE.getValue().equals(jwksCacheItem.getKeyUse()))
                .toList();
    }

    public Optional<JwksCacheItem> getEncryptionKey(String jwksUrl) {
        return queryTableStream(jwksUrl)
                .filter(
                        jwksCacheItem ->
                                KeyUse.ENCRYPTION.getValue().equals(jwksCacheItem.getKeyUse()))
                .findFirst();
    }
}
