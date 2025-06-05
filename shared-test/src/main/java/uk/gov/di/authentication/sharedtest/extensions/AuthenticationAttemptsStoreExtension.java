package uk.gov.di.authentication.sharedtest.extensions;

import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import software.amazon.awssdk.services.dynamodb.model.AttributeDefinition;
import software.amazon.awssdk.services.dynamodb.model.BillingMode;
import software.amazon.awssdk.services.dynamodb.model.CreateTableRequest;
import software.amazon.awssdk.services.dynamodb.model.KeySchemaElement;
import software.amazon.awssdk.services.dynamodb.model.KeyType;
import uk.gov.di.authentication.shared.entity.CountType;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.UserPermissionService;
import uk.gov.di.authentication.sharedtest.basetest.DynamoTestConfiguration;

import java.util.ArrayList;
import java.util.Optional;

public class AuthenticationAttemptsStoreExtension extends DynamoExtension
        implements AfterEachCallback {

    public static final String AUTHENTICATION_INTERNAL_SUB_ID_FIELD = "InternalSubjectId";
    public static final String AUTHENTICATION_JOURNEY_TYPE_COUNT_TYPE_FIELD = "SK";
    public static final String AUTHENTICATION_ATTEMPTS_STORE_TABLE = "local-authentication-attempt";

    private final UserPermissionService userPermissionService;
    private final ConfigurationService configuration;

    public AuthenticationAttemptsStoreExtension() {
        createInstance();
        this.configuration = new DynamoTestConfiguration(REGION, ENVIRONMENT, DYNAMO_ENDPOINT);
        userPermissionService = new UserPermissionService(configuration);
    }

    @Override
    public void afterEach(ExtensionContext context) throws Exception {
        clearDynamoTable(
                dynamoDB,
                AUTHENTICATION_ATTEMPTS_STORE_TABLE,
                AUTHENTICATION_INTERNAL_SUB_ID_FIELD,
                Optional.of(AUTHENTICATION_JOURNEY_TYPE_COUNT_TYPE_FIELD));
    }

    @Override
    protected void createTables() {
        if (!tableExists(AUTHENTICATION_ATTEMPTS_STORE_TABLE)) {
            createAuthenticationAttemptsTable();
        }
    }

    public void createOrIncrementCount(
            String internalSubId, long ttl, JourneyType journeyType, CountType countType) {
        userPermissionService.createOrIncrementCount(internalSubId, ttl, journeyType, countType);
    }

    public int getAuthenticationAttempt(
            String internalSubId, JourneyType journeyType, CountType countType) {
        return userPermissionService.getCount(internalSubId, journeyType, countType);
    }

    private void createAuthenticationAttemptsTable() {
        ArrayList<AttributeDefinition> attributeDefinitions = new ArrayList<>();
        attributeDefinitions.add(
                AttributeDefinition.builder()
                        .attributeName(AUTHENTICATION_INTERNAL_SUB_ID_FIELD)
                        .attributeType("S")
                        .build());
        attributeDefinitions.add(
                AttributeDefinition.builder()
                        .attributeName(AUTHENTICATION_JOURNEY_TYPE_COUNT_TYPE_FIELD)
                        .attributeType("S")
                        .build());

        ArrayList<KeySchemaElement> tableKeySchema = new ArrayList<>();
        tableKeySchema.add(
                KeySchemaElement.builder()
                        .attributeName(AUTHENTICATION_INTERNAL_SUB_ID_FIELD)
                        .keyType(KeyType.HASH)
                        .build());
        tableKeySchema.add(
                KeySchemaElement.builder()
                        .attributeName(AUTHENTICATION_JOURNEY_TYPE_COUNT_TYPE_FIELD)
                        .keyType(KeyType.RANGE)
                        .build());

        CreateTableRequest request =
                CreateTableRequest.builder()
                        .tableName(AUTHENTICATION_ATTEMPTS_STORE_TABLE)
                        .attributeDefinitions(attributeDefinitions)
                        .keySchema(tableKeySchema)
                        .billingMode(BillingMode.PAY_PER_REQUEST)
                        .build();

        dynamoDB.createTable(request);
    }
}
