package uk.gov.di.authentication.shared.services;

import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.enhanced.dynamodb.Key;
import software.amazon.awssdk.enhanced.dynamodb.TableSchema;
import uk.gov.di.authentication.shared.entity.IdentityCredentials;
import uk.gov.di.authentication.shared.helpers.NowHelper;

import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import static uk.gov.di.authentication.shared.dynamodb.DynamoClientHelper.createDynamoEnhancedClient;

public class DynamoIdentityService {

    private static final String IDENTITY_CREDENTIALS_TABLE = "identity-credentials";
    private final long timeToExist;
    private final DynamoDbTable<IdentityCredentials> dynamoIdentityCredentialsTable;

    public DynamoIdentityService(ConfigurationService configurationService) {
        var tableName = configurationService.getEnvironment() + "-" + IDENTITY_CREDENTIALS_TABLE;

        this.timeToExist = configurationService.getAccessTokenExpiry();
        var dynamoDbEnhancedClient = createDynamoEnhancedClient(configurationService);
        dynamoIdentityCredentialsTable =
                dynamoDbEnhancedClient.table(
                        tableName, TableSchema.fromBean(IdentityCredentials.class));

        warmUp();
    }

    public void addCoreIdentityJWT(String subjectID, String coreIdentityJWT) {
        var identityCredentials =
                Optional.ofNullable(
                                dynamoIdentityCredentialsTable.getItem(
                                        Key.builder().partitionValue(subjectID).build()))
                        .orElse(new IdentityCredentials());
        dynamoIdentityCredentialsTable.updateItem(
                identityCredentials
                        .withSubjectID(subjectID)
                        .withCoreIdentityJWT(coreIdentityJWT)
                        .withTimeToExist(
                                NowHelper.nowPlus(timeToExist, ChronoUnit.SECONDS)
                                        .toInstant()
                                        .getEpochSecond()));
    }

    public Optional<IdentityCredentials> getIdentityCredentials(String subjectID) {
        return Optional.ofNullable(
                        dynamoIdentityCredentialsTable.getItem(
                                Key.builder().partitionValue(subjectID).build()))
                .filter(t -> t.getTimeToExist() > NowHelper.now().toInstant().getEpochSecond());
    }

    public void deleteIdentityCredentials(String subjectID) {
        var identityCredentials =
                dynamoIdentityCredentialsTable.getItem(
                        Key.builder().partitionValue(subjectID).build());
        if (Objects.nonNull(identityCredentials)) {
            dynamoIdentityCredentialsTable.deleteItem(identityCredentials);
        }
    }

    public void saveIdentityClaims(
            String subjectID,
            Map<String, String> additionalClaims,
            String ipvVot,
            String ipvCoreIdentity) {
        var identityCredentials =
                new IdentityCredentials()
                        .withSubjectID(subjectID)
                        .withAdditionalClaims(additionalClaims)
                        .withIpvVot(ipvVot)
                        .withIpvCoreIdentity(ipvCoreIdentity)
                        .withTimeToExist(
                                NowHelper.nowPlus(timeToExist, ChronoUnit.SECONDS)
                                        .toInstant()
                                        .getEpochSecond());

        dynamoIdentityCredentialsTable.putItem(identityCredentials);
    }

    private void warmUp() {
        dynamoIdentityCredentialsTable.describeTable();
    }
}
