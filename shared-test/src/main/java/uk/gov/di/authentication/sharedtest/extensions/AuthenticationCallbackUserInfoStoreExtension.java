package uk.gov.di.authentication.sharedtest.extensions;

import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import software.amazon.awssdk.services.dynamodb.model.AttributeDefinition;
import software.amazon.awssdk.services.dynamodb.model.BillingMode;
import software.amazon.awssdk.services.dynamodb.model.CreateTableRequest;
import software.amazon.awssdk.services.dynamodb.model.KeySchemaElement;
import software.amazon.awssdk.services.dynamodb.model.KeyType;
import software.amazon.awssdk.services.dynamodb.model.ScalarAttributeType;
import uk.gov.di.authentication.shared.entity.AuthenticationUserInfo;
import uk.gov.di.authentication.shared.services.AuthenticationUserInfoStorageService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.sharedtest.basetest.DynamoTestConfiguration;

import java.util.Optional;

public class AuthenticationCallbackUserInfoStoreExtension extends DynamoExtension
        implements AfterEachCallback {

    public static final String CALLBACK_USERINFO_TABLE = "local-authentication-callback-userinfo";
    public static final String SUBJECT_ID_FIELD = "SubjectID";

    private AuthenticationUserInfoStorageService userInfoService;
    private final ConfigurationService configuration;

    public AuthenticationCallbackUserInfoStoreExtension(long ttl) {
        createInstance();
        this.configuration =
                new DynamoTestConfiguration(REGION, ENVIRONMENT, LOCALSTACK_ENDPOINT) {
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
        clearDynamoTable(dynamoDB, CALLBACK_USERINFO_TABLE, SUBJECT_ID_FIELD);
    }

    @Override
    protected void createTables() {
        if (!tableExists(CALLBACK_USERINFO_TABLE)) {
            createCallbackUserInfoTable(CALLBACK_USERINFO_TABLE);
        }
    }

    private void createCallbackUserInfoTable(String tableName) {
        CreateTableRequest request =
                CreateTableRequest.builder()
                        .tableName(tableName)
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

    public Optional<AuthenticationUserInfo> getUserInfoBySubjectId(String subjectId) {
        return userInfoService.getAuthenticationUserInfoData(subjectId);
    }

    public void addAuthenticationUserInfoData(String subjectId, UserInfo userInfo) {
        userInfoService.addAuthenticationUserInfoData(subjectId, userInfo);
    }
}
