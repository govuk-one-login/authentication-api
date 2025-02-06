package uk.gov.di.orchestration.sharedtest.extensions;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import software.amazon.awssdk.services.dynamodb.model.AttributeDefinition;
import software.amazon.awssdk.services.dynamodb.model.BillingMode;
import software.amazon.awssdk.services.dynamodb.model.CreateTableRequest;
import software.amazon.awssdk.services.dynamodb.model.KeySchemaElement;
import software.amazon.awssdk.services.dynamodb.model.KeyType;
import software.amazon.awssdk.services.dynamodb.model.ScalarAttributeType;
import uk.gov.di.orchestration.shared.services.AuthenticationUserInfoStorageService;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.sharedtest.basetest.DynamoTestConfiguration;

import java.util.Optional;

public class AuthenticationCallbackUserInfoStoreExtension extends DynamoExtension
        implements AfterEachCallback {

    public static final String OLD_AUTH_USERINFO_TABLE = "local-authentication-callback-userinfo";
    public static final String AUTH_USERINFO_TABLE = "local-Auth-User-Info";
    public static final String SUBJECT_ID_FIELD = "SubjectID";
    public static final String INTERNAL_COMMON_SUBJECT_ID_FIELD = "InternalCommonSubjectId";
    public static final String CLIENT_SESSION_ID_FIELD = "ClientSessionId";

    private AuthenticationUserInfoStorageService userInfoService;
    private final ConfigurationService configuration;

    public AuthenticationCallbackUserInfoStoreExtension(long ttl) {
        createInstance();
        this.configuration =
                new DynamoTestConfiguration(REGION, ENVIRONMENT, DYNAMO_ENDPOINT) {
                    @Override
                    public long getAccessTokenExpiry() {
                        return ttl;
                    }
                };
        userInfoService = new AuthenticationUserInfoStorageService(configuration);
    }

    @Override
    public void beforeAll(ExtensionContext context) throws Exception {
        super.beforeAll(context);

        userInfoService = new AuthenticationUserInfoStorageService(configuration);
    }

    @Override
    public void afterEach(ExtensionContext context) throws Exception {
        clearDynamoTable(dynamoDB, OLD_AUTH_USERINFO_TABLE, SUBJECT_ID_FIELD);
        clearDynamoTable(
                dynamoDB,
                AUTH_USERINFO_TABLE,
                INTERNAL_COMMON_SUBJECT_ID_FIELD,
                Optional.of(CLIENT_SESSION_ID_FIELD));
    }

    @Override
    protected void createTables() {
        if (!tableExists(OLD_AUTH_USERINFO_TABLE)) {
            createOldUserInfoTable();
        }
        if (!tableExists(AUTH_USERINFO_TABLE)) {
            createAuthUserInfoTable();
        }
    }

    private void createOldUserInfoTable() {
        CreateTableRequest request =
                CreateTableRequest.builder()
                        .tableName(OLD_AUTH_USERINFO_TABLE)
                        .keySchema(
                                KeySchemaElement.builder()
                                        .keyType(KeyType.HASH)
                                        .attributeName(SUBJECT_ID_FIELD)
                                        .build())
                        .billingMode(BillingMode.PAY_PER_REQUEST)
                        .attributeDefinitions(
                                AttributeDefinition.builder()
                                        .attributeName(SUBJECT_ID_FIELD)
                                        .attributeType(ScalarAttributeType.S)
                                        .build())
                        .build();
        dynamoDB.createTable(request);
    }

    private void createAuthUserInfoTable() {
        CreateTableRequest request =
                CreateTableRequest.builder()
                        .tableName(AUTH_USERINFO_TABLE)
                        .keySchema(
                                KeySchemaElement.builder()
                                        .keyType(KeyType.HASH)
                                        .attributeName(INTERNAL_COMMON_SUBJECT_ID_FIELD)
                                        .build(),
                                KeySchemaElement.builder()
                                        .keyType(KeyType.RANGE)
                                        .attributeName(CLIENT_SESSION_ID_FIELD)
                                        .build())
                        .billingMode(BillingMode.PAY_PER_REQUEST)
                        .attributeDefinitions(
                                AttributeDefinition.builder()
                                        .attributeName(INTERNAL_COMMON_SUBJECT_ID_FIELD)
                                        .attributeType(ScalarAttributeType.S)
                                        .build(),
                                AttributeDefinition.builder()
                                        .attributeName(CLIENT_SESSION_ID_FIELD)
                                        .attributeType(ScalarAttributeType.S)
                                        .build())
                        .build();
        dynamoDB.createTable(request);
    }

    public Optional<UserInfo> getAuthenticationUserInfo(String subjectId) throws ParseException {
        return userInfoService.getAuthenticationUserInfo(subjectId);
    }

    public void addAuthenticationUserInfoData(
            String subjectId, String clientSessionId, UserInfo userInfo) {
        userInfoService.addAuthenticationUserInfoData(subjectId, clientSessionId, userInfo);
    }
}
