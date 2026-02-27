package uk.gov.di.authentication.sharedtest.extensions;

import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import software.amazon.awssdk.services.dynamodb.model.AttributeDefinition;
import software.amazon.awssdk.services.dynamodb.model.BillingMode;
import software.amazon.awssdk.services.dynamodb.model.CreateTableRequest;
import software.amazon.awssdk.services.dynamodb.model.KeySchemaElement;
import software.amazon.awssdk.services.dynamodb.model.KeyType;

import java.util.ArrayList;
import java.util.Optional;

public class AuthenticatorExtension extends DynamoExtension implements AfterEachCallback {

    public static final String AUTHENTICATOR_TABLE = "local-authenticator";
    public static final String PUBLIC_SUBJECT_ID_FIELD = "PublicSubjectID";
    public static final String SORT_KEY_FIELD = "SK";

    public AuthenticatorExtension() {
        createInstance();
    }

    @Override
    public void afterEach(ExtensionContext context) throws Exception {
        clearDynamoTable(
                dynamoDB,
                AUTHENTICATOR_TABLE,
                PUBLIC_SUBJECT_ID_FIELD,
                Optional.of(SORT_KEY_FIELD));
    }

    @Override
    protected void createTables() {
        if (!tableExists(AUTHENTICATOR_TABLE)) {
            createAuthenticatorTable();
        }
    }

    private void createAuthenticatorTable() {
        ArrayList<AttributeDefinition> attributeDefinitions = new ArrayList<>();
        attributeDefinitions.add(
                AttributeDefinition.builder()
                        .attributeName(PUBLIC_SUBJECT_ID_FIELD)
                        .attributeType("S")
                        .build());
        attributeDefinitions.add(
                AttributeDefinition.builder()
                        .attributeName(SORT_KEY_FIELD)
                        .attributeType("S")
                        .build());

        ArrayList<KeySchemaElement> tableKeySchema = new ArrayList<>();
        tableKeySchema.add(
                KeySchemaElement.builder()
                        .attributeName(PUBLIC_SUBJECT_ID_FIELD)
                        .keyType(KeyType.HASH)
                        .build());
        tableKeySchema.add(
                KeySchemaElement.builder()
                        .attributeName(SORT_KEY_FIELD)
                        .keyType(KeyType.RANGE)
                        .build());

        CreateTableRequest request =
                CreateTableRequest.builder()
                        .tableName(AUTHENTICATOR_TABLE)
                        .attributeDefinitions(attributeDefinitions)
                        .keySchema(tableKeySchema)
                        .billingMode(BillingMode.PAY_PER_REQUEST)
                        .build();

        dynamoDB.createTable(request);
    }
}
