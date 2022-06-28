package uk.gov.di.authentication.shared.services;

import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBMapper;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.shared.dynamodb.DynamoClientHelper;
import uk.gov.di.authentication.shared.entity.CommonPassword;

import java.util.List;
import java.util.stream.Collectors;

import static uk.gov.di.authentication.shared.dynamodb.DynamoClientHelper.tableConfig;

public class CommonPasswordsService {
    private static final Logger LOG = LogManager.getLogger(CommonPasswordsService.class);
    private static final String COMMON_PASSWORDS_TABLE = "common-passwords";
    private final DynamoDBMapper commonPasswordsMapper;
    private final AmazonDynamoDB dynamoDB;

    public CommonPasswordsService(ConfigurationService configurationService) {
        String tableName = configurationService.getEnvironment() + "-" + COMMON_PASSWORDS_TABLE;
        this.dynamoDB = DynamoClientHelper.createDynamoClient(configurationService);
        this.commonPasswordsMapper = new DynamoDBMapper(dynamoDB, tableConfig(tableName));
        warmUp(tableName);
    }

    public boolean isCommonPassword(String password) {
        return commonPasswordsMapper.load(CommonPassword.class, password) != null;
    }

    public void addBatchCommonPasswords(List<String> passwords) {
        List<CommonPassword> commonPasswords =
                passwords.stream()
                        .map(password -> new CommonPassword().setPassword(password))
                        .collect(Collectors.toList());

        LOG.info("Add common passwords batch method called with {} items", commonPasswords.size());

        var result = commonPasswordsMapper.batchSave(commonPasswords);
        if (!result.isEmpty()) {
            LOG.error(
                    "Dynamo batch write returned failed batch, with {} failed batches",
                    result.size());

            Exception e = result.get(0).getException();

            result.get(0)
                    .getUnprocessedItems()
                    .forEach(
                            (key, value) ->
                                    value.forEach(
                                            writeRequest ->
                                                    LOG.error(
                                                            "Error produced by write request: {}",
                                                            writeRequest)));

            LOG.error("Batch write failed with exception", e);
        }
    }

    private void warmUp(String tableName) {
        dynamoDB.describeTable(tableName);
    }
}
