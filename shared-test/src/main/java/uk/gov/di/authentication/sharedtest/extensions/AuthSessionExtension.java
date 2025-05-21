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
import uk.gov.di.authentication.shared.entity.CredentialTrustLevel;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.NotificationType;
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

    public void addSession(String sessionId) {
        authSessionService.addSession(authSessionService.generateNewAuthSession(sessionId));
    }

    public void addEmailToSession(String sessionId, String email) {
        updateSession(getSession(sessionId).orElseThrow().withEmailAddress(email));
    }

    public void addClientIdToSession(String sessionId, String clientId) {
        updateSession(getSession(sessionId).orElseThrow().withClientId(clientId));
    }

    public void addRequestedCredentialStrengthToSession(
            String sessionId, CredentialTrustLevel credentialTrustLevel) {
        updateSession(
                getSession(sessionId)
                        .orElseThrow()
                        .withRequestedCredentialStrength(credentialTrustLevel));
    }

    public void addInternalCommonSubjectIdToSession(
            String sessionId, String internalCommonSubjectIdl) {
        updateSession(
                getSession(sessionId)
                        .orElseThrow()
                        .withInternalCommonSubjectId(internalCommonSubjectIdl));
    }

    public void addAchievedCredentialTrustToSession(
            String sessionId, CredentialTrustLevel credentialStrength) {
        updateSession(
                getSession(sessionId)
                        .orElseThrow()
                        .withAchievedCredentialStrength(credentialStrength));
    }

    public AuthSessionItem getUpdatedPreviousSessionOrCreateNew(
            Optional<String> previousSessionId,
            String sessionId,
            CredentialTrustLevel credentialTrustLevel) {
        return authSessionService.getUpdatedPreviousSessionOrCreateNew(
                previousSessionId, sessionId, credentialTrustLevel);
    }

    public void updateSession(AuthSessionItem sessionItem) {
        authSessionService.updateSession(sessionItem);
    }

    public Optional<AuthSessionItem> getSessionFromRequestHeaders(
            Map<String, String> requestHeaders) {
        return authSessionService.getSessionFromRequestHeaders(requestHeaders);
    }

    public void incrementSessionCodeRequestCount(
            String sessionId, NotificationType notificationType, JourneyType journeyType) {
        updateSession(
                getSession(sessionId)
                        .orElseThrow()
                        .incrementCodeRequestCount(notificationType, journeyType));
    }
}
