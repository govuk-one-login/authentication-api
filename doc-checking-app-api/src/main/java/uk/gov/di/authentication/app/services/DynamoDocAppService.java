package uk.gov.di.authentication.app.services;

import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.enhanced.dynamodb.Key;
import software.amazon.awssdk.enhanced.dynamodb.TableSchema;
import uk.gov.di.authentication.app.entity.DocAppCredential;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Optional;

import static uk.gov.di.authentication.shared.dynamodb.DynamoClientHelper.createDynamoEnhancedClient;

public class DynamoDocAppService {

    private static final String DOC_APP_CREDENTIAL_TABLE = "doc-app-credential";
    private final long timeToExist;
    private final DynamoDbTable<DocAppCredential> dynamoDocAppCredentialTable;

    public DynamoDocAppService(ConfigurationService configurationService) {
        var tableName = configurationService.getEnvironment() + "-" + DOC_APP_CREDENTIAL_TABLE;

        this.timeToExist = configurationService.getAccessTokenExpiry();
        var dynamoDbEnhancedClient = createDynamoEnhancedClient(configurationService);
        dynamoDocAppCredentialTable =
                dynamoDbEnhancedClient.table(
                        tableName, TableSchema.fromBean(DocAppCredential.class));
        warmUp();
    }

    public void addDocAppCredential(String subjectID, List<String> credential) {
        var docAppCredential =
                new DocAppCredential()
                        .withSubjectID(subjectID)
                        .withCredential(credential)
                        .withTimeToExist(
                                NowHelper.nowPlus(timeToExist, ChronoUnit.SECONDS)
                                        .toInstant()
                                        .getEpochSecond());

        dynamoDocAppCredentialTable.putItem(docAppCredential);
    }

    public Optional<DocAppCredential> getDocAppCredential(String subjectID) {
        return Optional.ofNullable(
                        dynamoDocAppCredentialTable.getItem(
                                Key.builder().partitionValue(subjectID).build()))
                .filter(t -> t.getTimeToExist() > NowHelper.now().toInstant().getEpochSecond());
    }

    public void deleteDocAppCredential(String subjectID) {
        dynamoDocAppCredentialTable.deleteItem(Key.builder().partitionValue(subjectID).build());
    }

    private void warmUp() {
        dynamoDocAppCredentialTable.describeTable();
    }
}
