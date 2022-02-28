package uk.gov.di.authentication.shared.dynamodb;

import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBMapper;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBMapperConfig;
import com.amazonaws.services.dynamodbv2.model.AttributeValue;
import com.amazonaws.services.dynamodbv2.model.Delete;

import java.util.Map;

public class DynamoDBSchemaHelper {

    private final AmazonDynamoDB dynamoDB;
    private final String environment;

    public DynamoDBSchemaHelper(AmazonDynamoDB dynamoDB, String environment) {
        this.dynamoDB = dynamoDB;
        this.environment = environment;
    }

    public enum Table {
        USER_CREDENTIALS_TABLE("user-credentials", "Email"),
        USER_PROFILE_TABLE("user-profile", "Email");

        private final String tableName;
        private final String primaryKey;

        Table(String tableName, String primaryKey) {
            this.tableName = tableName;
            this.primaryKey = primaryKey;
        }

        public String getTableName() {
            return tableName;
        }

        public String getPrimaryKey() {
            return primaryKey;
        }
    }

    public String getFullyQualifiedTableName(Table table) {
        return environment + "-" + table.getTableName();
    }

    public DynamoDBMapper buildConfiguredDynamoDBMapper(Table table) {
        return new DynamoDBMapper(
                dynamoDB,
                new DynamoDBMapperConfig.Builder()
                        .withTableNameOverride(
                                DynamoDBMapperConfig.TableNameOverride.withTableNameReplacement(
                                        getFullyQualifiedTableName(table)))
                        .build());
    }

    public Delete buildDelete(Table table, AttributeValue attributeValue) {
        return new Delete()
                .withTableName(getFullyQualifiedTableName(table))
                .withKey(Map.of(table.getPrimaryKey(), attributeValue));
    }
}
