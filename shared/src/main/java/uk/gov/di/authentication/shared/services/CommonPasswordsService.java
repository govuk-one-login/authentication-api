package uk.gov.di.authentication.shared.services;

import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBMapper;
import uk.gov.di.authentication.shared.dynamodb.DynamoClientHelper;
import uk.gov.di.authentication.shared.entity.CommonPassword;

import static uk.gov.di.authentication.shared.dynamodb.DynamoClientHelper.tableConfig;

public class CommonPasswordsService {

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

    private void warmUp(String tableName) {
        dynamoDB.describeTable(tableName);
    }
}
