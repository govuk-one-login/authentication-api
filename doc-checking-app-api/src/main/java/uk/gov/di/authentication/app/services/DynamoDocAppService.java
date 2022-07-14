package uk.gov.di.authentication.app.services;

import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBMapper;
import uk.gov.di.authentication.app.entity.DocAppCredential;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Optional;

import static uk.gov.di.authentication.shared.dynamodb.DynamoClientHelper.createDynamoClient;
import static uk.gov.di.authentication.shared.dynamodb.DynamoClientHelper.tableConfig;

public class DynamoDocAppService {

    private static final String DOC_APP_CREDENTIAL_TABLE = "doc-app-credential";
    private final DynamoDBMapper docAppCredentialMapper;
    private final long timeToExist;
    private final AmazonDynamoDB dynamoDB;

    public DynamoDocAppService(ConfigurationService configurationService) {
        var tableName = configurationService.getEnvironment() + "-" + DOC_APP_CREDENTIAL_TABLE;

        this.timeToExist = configurationService.getAccessTokenExpiry();
        this.dynamoDB = createDynamoClient(configurationService);
        this.docAppCredentialMapper = new DynamoDBMapper(dynamoDB, tableConfig(tableName));
        warmUp(tableName);
    }

    public void addDocAppCredential(String subjectID, List<String> credential) {
        var docAppCredential =
                new DocAppCredential()
                        .setSubjectID(subjectID)
                        .setCredential(credential)
                        .setTimeToExist(
                                NowHelper.nowPlus(timeToExist, ChronoUnit.SECONDS)
                                        .toInstant()
                                        .getEpochSecond());

        docAppCredentialMapper.save(docAppCredential);
    }

    public Optional<DocAppCredential> getDocAppCredential(String subjectID) {
        return Optional.ofNullable(docAppCredentialMapper.load(DocAppCredential.class, subjectID))
                .filter(t -> t.getTimeToExist() > NowHelper.now().toInstant().getEpochSecond());
    }

    public void deleteDocAppCredential(String subjectID) {
        docAppCredentialMapper.delete(
                docAppCredentialMapper.load(DocAppCredential.class, subjectID));
    }

    private void warmUp(String tableName) {
        dynamoDB.describeTable(tableName);
    }
}
