package uk.gov.di.authentication.shared.services;

import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBMapper;
import uk.gov.di.authentication.shared.dynamodb.DynamoClientHelper;
import uk.gov.di.authentication.shared.entity.SPOTCredential;

import java.util.Optional;

import static uk.gov.di.authentication.shared.dynamodb.DynamoClientHelper.tableConfig;

public class DynamoSpotService {

    private static final String SPOT_CREDENTIAL_TABLE = "spot-credential";
    private final DynamoDBMapper spotCredentialMapper;
    private final long timeToExist;
    private final AmazonDynamoDB dynamoDB;

    public DynamoSpotService(ConfigurationService configurationService) {
        var tableName = configurationService.getEnvironment() + "-" + SPOT_CREDENTIAL_TABLE;

        this.timeToExist = configurationService.getAccessTokenExpiry();
        this.dynamoDB = DynamoClientHelper.createDynamoClient(configurationService);
        this.spotCredentialMapper = new DynamoDBMapper(dynamoDB, tableConfig(tableName));

        warmUp(tableName);
    }

    public void addSpotResponse(String subjectID, String serializedCredential) {
        var spotCredential =
                new SPOTCredential()
                        .setSubjectID(subjectID)
                        .setSerializedCredential(serializedCredential)
                        .setTimeToExist(timeToExist);

        spotCredentialMapper.save(spotCredential);
    }

    public Optional<SPOTCredential> getSpotCredential(String subjectID) {
        return Optional.ofNullable(spotCredentialMapper.load(SPOTCredential.class, subjectID));
    }

    public void removeSpotCredential(String subjectID) {
        spotCredentialMapper.delete(spotCredentialMapper.load(SPOTCredential.class, subjectID));
    }

    private void warmUp(String tableName) {
        dynamoDB.describeTable(tableName);
    }
}
