package uk.gov.di.authentication.app.services;

import com.amazonaws.client.builder.AwsClientBuilder;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDBClientBuilder;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBMapper;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBMapperConfig;
import uk.gov.di.authentication.app.entity.DocAppCredential;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.util.Optional;

public class DynamoDocAppService {

    private static final String DOC_APP_CREDENTIAL_TABLE = "doc-app-credential";
    private final DynamoDBMapper docAppCredentialMapper;
    private final long timeToExist;
    private final AmazonDynamoDB dynamoDB;

    public DynamoDocAppService(ConfigurationService configurationService) {
        this(
                configurationService.getAwsRegion(),
                configurationService.getEnvironment(),
                configurationService.getDynamoEndpointUri(),
                configurationService.getAccessTokenExpiry());
    }

    public DynamoDocAppService(
            String region, String environment, Optional<String> dynamoEndpoint, long timeToExist) {
        this.timeToExist = timeToExist;
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
        DynamoDBMapperConfig docAppConfig =
                new DynamoDBMapperConfig.Builder()
                        .withTableNameOverride(
                                DynamoDBMapperConfig.TableNameOverride.withTableNameReplacement(
                                        environment + "-" + DOC_APP_CREDENTIAL_TABLE))
                        .withConsistentReads(DynamoDBMapperConfig.ConsistentReads.CONSISTENT)
                        .build();
        this.docAppCredentialMapper = new DynamoDBMapper(dynamoDB, docAppConfig);
        warmUp(environment + "-" + DOC_APP_CREDENTIAL_TABLE);
    }

    public void addDocAppCredential(String subjectID, String credential) {
        var docAppCredential =
                new DocAppCredential()
                        .setSubjectID(subjectID)
                        .setCredential(credential)
                        .setTimeToExist(timeToExist);

        docAppCredentialMapper.save(docAppCredential);
    }

    public Optional<DocAppCredential> getDocAppCredential(String subjectID) {
        return Optional.ofNullable(docAppCredentialMapper.load(DocAppCredential.class, subjectID));
    }

    public void deleteDocAppCredential(String subjectID) {
        docAppCredentialMapper.delete(
                docAppCredentialMapper.load(DocAppCredential.class, subjectID));
    }

    private void warmUp(String tableName) {
        dynamoDB.describeTable(tableName);
    }
}
