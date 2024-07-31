package uk.gov.di.authentication.sharedtest.extensions;

import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import software.amazon.awssdk.services.dynamodb.model.AttributeDefinition;
import software.amazon.awssdk.services.dynamodb.model.BillingMode;
import software.amazon.awssdk.services.dynamodb.model.CreateTableRequest;
import software.amazon.awssdk.services.dynamodb.model.KeySchemaElement;
import software.amazon.awssdk.services.dynamodb.model.KeyType;
import software.amazon.awssdk.services.dynamodb.model.ScalarAttributeType;
import uk.gov.di.authentication.shared.entity.AuthenticationAttempts;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoAuthenticationAttemptsService;
import uk.gov.di.authentication.sharedtest.basetest.DynamoTestConfiguration;

import java.util.Optional;

public class AuthenticationAttemptsStoreExtension extends DynamoExtension
        implements AfterEachCallback {

    public static final String AUTHENTICATION_ATTEMPTS_FIELD = "AttemptIdentifier";
    public static final String AUTHENTICATION_ATTEMPTS_STORE_TABLE =
            "local-authentication-attempts";

    private DynamoAuthenticationAttemptsService dynamoService;
    private final ConfigurationService configuration;

    public AuthenticationAttemptsStoreExtension() {
        createInstance();
        this.configuration = new DynamoTestConfiguration(REGION, ENVIRONMENT, DYNAMO_ENDPOINT);
        dynamoService = new DynamoAuthenticationAttemptsService(configuration);
    }

    @Override
    public void afterEach(ExtensionContext context) throws Exception {
        clearDynamoTable(
                dynamoDB, AUTHENTICATION_ATTEMPTS_STORE_TABLE, AUTHENTICATION_ATTEMPTS_FIELD);
    }

    @Override
    protected void createTables() {
        if (!tableExists(AUTHENTICATION_ATTEMPTS_STORE_TABLE)) {
            createAuthenticationAttemptsTable();
        }
    }

    public void createOrIncrementCount(
            String attemptIdentifier, long ttl, String authenticationMethod) {
        dynamoService.createOrIncrementCount(attemptIdentifier, ttl, authenticationMethod);
    }

    public Optional<AuthenticationAttempts> getAuthenticationAttempts(String attemptIdentifier) {
        return dynamoService.getAuthenticationAttempts(attemptIdentifier);
    }

    private void createAuthenticationAttemptsTable() {
        CreateTableRequest request =
                CreateTableRequest.builder()
                        .tableName(AUTHENTICATION_ATTEMPTS_STORE_TABLE)
                        .keySchema(
                                KeySchemaElement.builder()
                                        .keyType(KeyType.HASH)
                                        .attributeName(AUTHENTICATION_ATTEMPTS_FIELD)
                                        .build())
                        .billingMode(BillingMode.PAY_PER_REQUEST)
                        .attributeDefinitions(
                                AttributeDefinition.builder()
                                        .attributeName(AUTHENTICATION_ATTEMPTS_FIELD)
                                        .attributeType(ScalarAttributeType.S)
                                        .build())
                        .build();

        dynamoDB.createTable(request);
    }
}
