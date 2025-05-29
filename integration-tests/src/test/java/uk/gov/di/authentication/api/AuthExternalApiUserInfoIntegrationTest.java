package uk.gov.di.authentication.api;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import com.nimbusds.openid.connect.sdk.UserInfoErrorResponse;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import software.amazon.awssdk.core.SdkBytes;
import uk.gov.di.authentication.external.domain.AuthExternalApiAuditableEvent;
import uk.gov.di.authentication.external.entity.AuthUserInfoClaims;
import uk.gov.di.authentication.external.lambda.UserInfoHandler;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;
import uk.gov.di.authentication.sharedtest.extensions.AccessTokenStoreExtension;
import uk.gov.di.authentication.sharedtest.extensions.AuthSessionExtension;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static com.nimbusds.oauth2.sdk.token.BearerTokenError.INVALID_TOKEN;
import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.authentication.shared.domain.RequestHeaders.SESSION_ID_HEADER;
import static uk.gov.di.authentication.shared.helpers.TxmaAuditHelper.TXMA_AUDIT_ENCODED_HEADER;
import static uk.gov.di.authentication.sharedtest.helper.AuditAssertionsHelper.assertTxmaAuditEventsSubmittedWithMatchingNames;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class AuthExternalApiUserInfoIntegrationTest extends ApiGatewayHandlerIntegrationTest {
    private static final String RP_SECTOR_ID_HOST = "rp-test-uri.com";
    private static final String INTERNAL_SECTOR_ID_HOST = "test.account.gov.uk";
    private static final String TEST_EMAIL_ADDRESS = "joe.bloggs@digital.cabinet-office.gov.uk";
    private static final String TEST_PHONE_NUMBER = "01234567890";
    private static final String TEST_PASSWORD = "password-1";
    private static final Subject TEST_SUBJECT = new Subject();
    private static final String TEST_SESSION_ID = UUID.randomUUID().toString();
    public static final String ENCODED_DEVICE_DETAILS =
            "YTtKVSlub1YlOSBTeEI4J3pVLVd7Jjl8VkBfREs2N3clZmN+fnU7fXNbcTJjKyEzN2IuUXIgMGttV058fGhUZ0xhenZUdldEblB8SH18XypwXUhWPXhYXTNQeURW%";

    @RegisterExtension
    protected static final AccessTokenStoreExtension accessTokenStoreExtension =
            new AccessTokenStoreExtension(180);

    private static final AuthSessionExtension authSessionExtension = new AuthSessionExtension();

    @BeforeEach
    void setup() throws Json.JsonException {
        var configurationService =
                new IntegrationTestConfigurationService(
                        notificationsQueue,
                        tokenSigner,
                        docAppPrivateKeyJwtSigner,
                        configurationParameters) {

                    @Override
                    public String getTxmaAuditQueueUrl() {
                        return txmaAuditQueue.getQueueUrl();
                    }
                };
        txmaAuditQueue.clear();
        handler = new UserInfoHandler(configurationService);
        withRedisSession();
    }

    @Test
    void
            shouldCallUserInfoWithAccessTokenAndReturn200WithASingleRequestedClaimAndTwoUnconditionalClaimsButNotClaimsWhichAreNotInAccessToken()
                    throws ParseException {
        String accessTokenAsString = UUID.randomUUID().toString();
        var accessToken = new BearerAccessToken(accessTokenAsString);
        boolean isNewAccount = true;
        var createdUser =
                addTokenToDynamoAndCreateAssociatedUser(
                        accessTokenAsString,
                        List.of(OIDCScopeValue.EMAIL.getValue()),
                        isNewAccount);
        withAuthSessionNewAccount();

        var response =
                makeRequest(
                        Optional.empty(),
                        Map.ofEntries(
                                Map.entry("Authorization", accessToken.toAuthorizationHeader()),
                                Map.entry(TXMA_AUDIT_ENCODED_HEADER, ENCODED_DEVICE_DETAILS),
                                Map.entry(SESSION_ID_HEADER, TEST_SESSION_ID)),
                        Map.of());

        assertThat(response, hasStatus(200));

        var rpPairwiseId =
                ClientSubjectHelper.calculatePairwiseIdentifier(
                        TEST_SUBJECT.getValue(),
                        RP_SECTOR_ID_HOST,
                        SdkBytes.fromByteBuffer(createdUser.getSalt()).asByteArray());
        var internalPairwiseId =
                ClientSubjectHelper.calculatePairwiseIdentifier(
                        TEST_SUBJECT.getValue(),
                        INTERNAL_SECTOR_ID_HOST,
                        SdkBytes.fromByteBuffer(createdUser.getSalt()).asByteArray());
        var userInfoResponse = UserInfo.parse(response.getBody());
        assertEquals(userInfoResponse.getSubject().getValue(), internalPairwiseId);
        assertThat(userInfoResponse.getClaim("rp_pairwise_id"), equalTo(rpPairwiseId));
        assertThat(userInfoResponse.getClaim("new_account"), equalTo(isNewAccount));
        assertThat(
                userInfoResponse.getClaim(OIDCScopeValue.EMAIL.getValue()),
                equalTo(TEST_EMAIL_ADDRESS));

        assertNull(userInfoResponse.getClaim("legacy_subject_id"));
        assertNull(userInfoResponse.getClaim("public_subject_id"));
        assertNull(userInfoResponse.getClaim("local_account_id"));
        assertNull(userInfoResponse.getPhoneNumber());
        assertNull(userInfoResponse.getPhoneNumberVerified());
        assertNull(userInfoResponse.getClaim("salt"));
        assertNull(userInfoResponse.getClaim("verified_mfa_method_type"));
        assertNull(userInfoResponse.getClaim("uplift_required"));

        assertThat(
                authSessionExtension.getSession(TEST_SESSION_ID).get().getIsNewAccount(),
                equalTo(AuthSessionItem.AccountState.EXISTING));

        assertTrue(accessTokenStoreExtension.getAccessToken(accessTokenAsString).get().isUsed());
        assertTxmaAuditEventsSubmittedWithMatchingNames(
                txmaAuditQueue,
                singletonList(AuthExternalApiAuditableEvent.AUTH_USERINFO_SENT_TO_ORCHESTRATION));
    }

    @Test
    void shouldUpdateAuthSessionWithAccountStateExisting() {
        String accessTokenAsString = UUID.randomUUID().toString();
        var accessToken = new BearerAccessToken(accessTokenAsString);
        addTokenToDynamoAndCreateAssociatedUser(
                accessTokenAsString, List.of(OIDCScopeValue.EMAIL.getValue()), true);
        withAuthSessionNewAccount();

        var response =
                makeRequest(
                        Optional.empty(),
                        Map.ofEntries(
                                Map.entry("Authorization", accessToken.toAuthorizationHeader()),
                                Map.entry(TXMA_AUDIT_ENCODED_HEADER, ENCODED_DEVICE_DETAILS),
                                Map.entry(SESSION_ID_HEADER, TEST_SESSION_ID)),
                        Map.of());

        assertThat(response, hasStatus(200));
        assertThat(
                authSessionExtension.getSession(TEST_SESSION_ID).get().getIsNewAccount(),
                equalTo(AuthSessionItem.AccountState.EXISTING));
    }

    @Test
    void shouldReturnClaimsIfRequestedInTheToken() throws ParseException {
        String accessTokenAsString = UUID.randomUUID().toString();
        var accessToken = new BearerAccessToken(accessTokenAsString);
        addTokenToDynamoAndCreateAssociatedUser(
                accessTokenAsString,
                List.of(
                        OIDCScopeValue.EMAIL.getValue(),
                        AuthUserInfoClaims.VERIFIED_MFA_METHOD_TYPE.getValue(),
                        AuthUserInfoClaims.UPLIFT_REQUIRED.getValue()),
                true);
        withAuthSessionNewAccount();

        var response =
                makeRequest(
                        Optional.empty(),
                        Map.ofEntries(
                                Map.entry("Authorization", accessToken.toAuthorizationHeader()),
                                Map.entry(TXMA_AUDIT_ENCODED_HEADER, ENCODED_DEVICE_DETAILS),
                                Map.entry(SESSION_ID_HEADER, TEST_SESSION_ID)),
                        Map.of());

        assertThat(response, hasStatus(200));

        var userInfoResponse = UserInfo.parse(response.getBody());
        assertThat(
                userInfoResponse.getClaim(AuthUserInfoClaims.VERIFIED_MFA_METHOD_TYPE.getValue()),
                equalTo("AUTH_APP"));
        assertTrue(
                (Boolean) userInfoResponse.getClaim(AuthUserInfoClaims.UPLIFT_REQUIRED.getValue()));
    }

    @Test
    void shouldReturn400WheNoAuthSessionPresent() {
        String accessTokenAsString = UUID.randomUUID().toString();
        var accessToken = new BearerAccessToken(accessTokenAsString);

        var response =
                makeRequest(
                        Optional.empty(),
                        Map.ofEntries(
                                Map.entry("Authorization", accessToken.toAuthorizationHeader()),
                                Map.entry(SESSION_ID_HEADER, TEST_SESSION_ID)),
                        Map.of());

        assertThat(response, hasStatus(400));
        assertThat(response, hasJsonBody(ErrorResponse.ERROR_1000));
    }

    @Test
    void shouldReturn401ForAccessTokenThatDoesNotExistInDatabase() {
        withAuthSessionNewAccount();
        var accessToken =
                new BearerAccessToken("any-as-we-will-not-be-seeding-this-into-the-test-db");

        var response =
                makeRequest(
                        Optional.empty(),
                        Map.ofEntries(
                                Map.entry("Authorization", accessToken.toAuthorizationHeader()),
                                Map.entry(SESSION_ID_HEADER, TEST_SESSION_ID)),
                        Map.of());

        assertThat(response, hasStatus(401));
        assertThat(
                response.getMultiValueHeaders().get("WWW-Authenticate"),
                equalTo(
                        new UserInfoErrorResponse(INVALID_TOKEN)
                                .toHTTPResponse()
                                .getHeaderMap()
                                .get("WWW-Authenticate")));
        assertThat(
                authSessionExtension.getSession(TEST_SESSION_ID).get().getIsNewAccount(),
                equalTo(AuthSessionItem.AccountState.NEW));
    }

    @Test
    void shouldReturn401ForAccessTokenThatIsAlreadyUsed() {
        withAuthSessionNewAccount();
        String accessTokenAsString = UUID.randomUUID().toString();
        var accessToken = new BearerAccessToken(accessTokenAsString);
        boolean isNewAccount = true;
        addTokenToDynamoAndCreateAssociatedUser(
                accessTokenAsString, List.of(OIDCScopeValue.EMAIL.getValue()), isNewAccount);

        accessTokenStoreExtension.setAccessTokenStoreUsed(accessTokenAsString, true);

        var response =
                makeRequest(
                        Optional.empty(),
                        Map.ofEntries(
                                Map.entry("Authorization", accessToken.toAuthorizationHeader()),
                                Map.entry(SESSION_ID_HEADER, TEST_SESSION_ID)),
                        Map.of());

        assertThat(response, hasStatus(401));
        assertThat(
                response.getMultiValueHeaders().get("WWW-Authenticate"),
                equalTo(
                        new UserInfoErrorResponse(INVALID_TOKEN)
                                .toHTTPResponse()
                                .getHeaderMap()
                                .get("WWW-Authenticate")));
        assertThat(
                authSessionExtension.getSession(TEST_SESSION_ID).get().getIsNewAccount(),
                equalTo(AuthSessionItem.AccountState.NEW));
        assertTrue(accessTokenStoreExtension.getAccessToken(accessTokenAsString).get().isUsed());
    }

    @Test
    void shouldReturn401ForAccessTokenThatIsPastItsTtl() {
        withAuthSessionNewAccount();
        String accessTokenAsString = UUID.randomUUID().toString();
        var accessToken = new BearerAccessToken(accessTokenAsString);
        boolean isNewAccount = true;
        addTokenToDynamoAndCreateAssociatedUser(
                accessTokenAsString, List.of(OIDCScopeValue.EMAIL.getValue()), isNewAccount);
        accessTokenStoreExtension.setAccessTokenTtlToZero(accessTokenAsString);

        var response =
                makeRequest(
                        Optional.empty(),
                        Map.ofEntries(
                                Map.entry("Authorization", accessToken.toAuthorizationHeader()),
                                Map.entry(SESSION_ID_HEADER, TEST_SESSION_ID)),
                        Map.of());

        assertThat(response, hasStatus(401));
        assertThat(
                response.getMultiValueHeaders().get("WWW-Authenticate"),
                equalTo(
                        new UserInfoErrorResponse(INVALID_TOKEN)
                                .toHTTPResponse()
                                .getHeaderMap()
                                .get("WWW-Authenticate")));
        assertThat(
                authSessionExtension.getSession(TEST_SESSION_ID).get().getIsNewAccount(),
                equalTo(AuthSessionItem.AccountState.NEW));
    }

    private UserProfile addTokenToDynamoAndCreateAssociatedUser(
            String accessToken, List<String> claims, boolean isNewAccount) {
        accessTokenStoreExtension.addAccessTokenStore(
                accessToken,
                TEST_SUBJECT.getValue(),
                claims,
                isNewAccount,
                RP_SECTOR_ID_HOST,
                1710255455L);

        userStore.signUp(TEST_EMAIL_ADDRESS, TEST_PASSWORD, TEST_SUBJECT);
        userStore.addVerifiedPhoneNumber(TEST_EMAIL_ADDRESS, TEST_PHONE_NUMBER);
        return userStore.getUserProfileFromEmail(TEST_EMAIL_ADDRESS).get();
    }

    private void withRedisSession() throws Json.JsonException {
        redis.createSession(TEST_SESSION_ID);
    }

    private void withAuthSessionNewAccount() {
        authSessionExtension.addSession(TEST_SESSION_ID);
        authSessionExtension.updateSession(
                authSessionExtension
                        .getSession(TEST_SESSION_ID)
                        .get()
                        .withAccountState(AuthSessionItem.AccountState.NEW)
                        .withVerifiedMfaMethodType(MFAMethodType.AUTH_APP)
                        .withUpliftRequired(true));
    }
}
