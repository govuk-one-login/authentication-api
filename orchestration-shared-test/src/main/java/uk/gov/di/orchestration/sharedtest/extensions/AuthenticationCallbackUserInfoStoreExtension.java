package uk.gov.di.orchestration.sharedtest.extensions;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import uk.gov.di.orchestration.shared.services.AuthenticationUserInfoStorageService;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.sharedtest.basetest.DynamoTestConfiguration;

import java.util.Optional;

public class AuthenticationCallbackUserInfoStoreExtension extends DynamoExtension
        implements AfterEachCallback {

    public static final String AUTH_USERINFO_TABLE = "local-Auth-User-Info";
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
        clearDynamoTable(
                dynamoDB,
                AUTH_USERINFO_TABLE,
                INTERNAL_COMMON_SUBJECT_ID_FIELD,
                Optional.of(CLIENT_SESSION_ID_FIELD));
    }

    @Override
    protected void createTables() {
        createTableWithPartitionAndSortKey(
                AUTH_USERINFO_TABLE, INTERNAL_COMMON_SUBJECT_ID_FIELD, CLIENT_SESSION_ID_FIELD);
    }

    public Optional<UserInfo> getAuthenticationUserInfo(String subjectId, String clientSessionId)
            throws ParseException {
        return userInfoService.getAuthenticationUserInfo(subjectId, clientSessionId);
    }

    public void addAuthenticationUserInfoData(
            String subjectId, String clientSessionId, UserInfo userInfo) {
        userInfoService.addAuthenticationUserInfoData(subjectId, clientSessionId, userInfo);
    }
}
