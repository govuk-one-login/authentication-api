package uk.gov.di.authentication.sharedtest.extensions;

import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import software.amazon.awssdk.services.dynamodb.model.AttributeDefinition;
import software.amazon.awssdk.services.dynamodb.model.BillingMode;
import software.amazon.awssdk.services.dynamodb.model.CreateTableRequest;
import software.amazon.awssdk.services.dynamodb.model.KeySchemaElement;
import software.amazon.awssdk.services.dynamodb.model.KeyType;
import software.amazon.awssdk.services.dynamodb.model.ScalarAttributeType;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.services.AuthSessionService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.sharedtest.basetest.DynamoTestConfiguration;

import java.util.Map;
import java.util.Optional;

public class AuthSessionExtension extends DynamoExtension implements AfterEachCallback {

    public static final String TABLE_NAME = "local-auth-session";
    public static final String SESSION_ID_FIELD = "SessionId";
    private AuthSessionService authSessionService;
    private final ConfigurationService configuration;

    public AuthSessionExtension() {
        createInstance();
        this.configuration = new DynamoTestConfiguration(REGION, ENVIRONMENT, DYNAMO_ENDPOINT);
        authSessionService = new AuthSessionService(configuration);
    }

    @Override
    public void beforeAll(ExtensionContext context) throws Exception {
        super.beforeAll(context);

        authSessionService = new AuthSessionService(configuration);
    }

    @Override
    public void afterEach(ExtensionContext context) throws Exception {
        clearDynamoTable(dynamoDB, TABLE_NAME, SESSION_ID_FIELD);
    }

    @Override
    protected void createTables() {
        if (!tableExists(TABLE_NAME)) {
            createAuthSessionTable();
        }
    }

    private void createAuthSessionTable() {
        CreateTableRequest request =
                CreateTableRequest.builder()
                        .tableName(TABLE_NAME)
                        .keySchema(
                                KeySchemaElement.builder()
                                        .keyType(KeyType.HASH)
                                        .attributeName(SESSION_ID_FIELD)
                                        .build())
                        .billingMode(BillingMode.PAY_PER_REQUEST)
                        .attributeDefinitions(
                                AttributeDefinition.builder()
                                        .attributeName(SESSION_ID_FIELD)
                                        .attributeType(ScalarAttributeType.S)
                                        .build())
                        .build();
        dynamoDB.createTable(request);
    }

    public Optional<AuthSessionItem> getSession(String sessionId) {
        return authSessionService.getSession(sessionId);
    }

    public void addSession(Optional<String> previousSessionId, String sessionId) {
        authSessionService.addOrUpdateSessionIncludingSessionId(
                previousSessionId, sessionId, null, false);
    }

    public void addSession(String sessionId) {
        authSessionService.addSession(authSessionService.generateNewAuthSession(sessionId));
    }

    public void updateSession(AuthSessionItem sessionItem) {
        authSessionService.updateSession(sessionItem);
    }

    public Optional<AuthSessionItem> getSessionFromRequestHeaders(
            Map<String, String> requestHeaders) {
        return authSessionService.getSessionFromRequestHeaders(requestHeaders);
    }
}
