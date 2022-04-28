package uk.gov.di.authentication.shared.dynamodb;

import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBMapper;
import com.amazonaws.services.dynamodbv2.model.AttributeValue;
import com.amazonaws.services.dynamodbv2.model.Delete;
import com.amazonaws.services.dynamodbv2.model.Put;

import java.util.Map;

import static uk.gov.di.authentication.shared.dynamodb.DynamoClientHelper.tableConfig;

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
        return new DynamoDBMapper(dynamoDB, tableConfig(getFullyQualifiedTableName(table)));
    }

    public Delete buildDelete(Table table, AttributeValue attributeValue) {
        return new Delete()
                .withTableName(getFullyQualifiedTableName(table))
                .withKey(Map.of(table.getPrimaryKey(), attributeValue));
    }

    public Put buildPut(Table table, DynamoDBItem item) {
        return new Put().withTableName(getFullyQualifiedTableName(table)).withItem(item.toItem());
    }
}
