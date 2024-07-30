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
import uk.gov.di.authentication.external.lambda.UserInfoHandler;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;
import uk.gov.di.authentication.sharedtest.extensions.AccessTokenStoreExtension;

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
import static uk.gov.di.authentication.shared.lambda.BaseFrontendHandler.TXMA_AUDIT_ENCODED_HEADER;
import static uk.gov.di.authentication.sharedtest.helper.AuditAssertionsHelper.assertTxmaAuditEventsSubmittedWithMatchingNames;
import static uk.gov.di.authentication.sharedtest.helper.CommonTestVariables.*;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class AuthExternalApiUserInfoIntegrationTest extends ApiGatewayHandlerIntegrationTest {
    private static final String RP_SECTOR_ID_HOST = "rp-test-uri.com";
    private static final Subject TEST_SUBJECT = new Subject();

    @RegisterExtension
    protected static final AccessTokenStoreExtension accessTokenStoreExtension =
            new AccessTokenStoreExtension(180);

    @BeforeEach
    void setup() {
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

        handler = new UserInfoHandler(configurationService);
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

        var response =
                makeRequest(
                        Optional.empty(),
                        Map.ofEntries(
                                Map.entry("Authorization", accessToken.toAuthorizationHeader()),
                                Map.entry(TXMA_AUDIT_ENCODED_HEADER, ENCODED_DEVICE_DETAILS)),
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
                        INTERNAL_SECTOR_HOST,
                        SdkBytes.fromByteBuffer(createdUser.getSalt()).asByteArray());
        var userInfoResponse = UserInfo.parse(response.getBody());
        assertEquals(userInfoResponse.getSubject().getValue(), internalPairwiseId);
        assertThat(userInfoResponse.getClaim("rp_pairwise_id"), equalTo(rpPairwiseId));
        assertThat(userInfoResponse.getClaim("new_account"), equalTo(isNewAccount));
        assertThat(userInfoResponse.getClaim(OIDCScopeValue.EMAIL.getValue()), equalTo(EMAIL));

        assertNull(userInfoResponse.getClaim("legacy_subject_id"));
        assertNull(userInfoResponse.getClaim("public_subject_id"));
        assertNull(userInfoResponse.getClaim("local_account_id"));
        assertNull(userInfoResponse.getPhoneNumber());
        assertNull(userInfoResponse.getPhoneNumberVerified());
        assertNull(userInfoResponse.getClaim("salt"));

        assertTrue(accessTokenStoreExtension.getAccessToken(accessTokenAsString).get().isUsed());
        assertTxmaAuditEventsSubmittedWithMatchingNames(
                txmaAuditQueue,
                singletonList(AuthExternalApiAuditableEvent.USERINFO_SENT_TO_ORCHESTRATION));
    }

    @Test
    void shouldReturn401ForAccessTokenThatDoesNotExistInDatabase() {
        var accessToken =
                new BearerAccessToken("any-as-we-will-not-be-seeding-this-into-the-test-db");

        var response =
                makeRequest(
                        Optional.empty(),
                        Map.of("Authorization", accessToken.toAuthorizationHeader()),
                        Map.of());

        assertThat(response, hasStatus(401));
        assertThat(
                response.getMultiValueHeaders().get("WWW-Authenticate"),
                equalTo(
                        new UserInfoErrorResponse(INVALID_TOKEN)
                                .toHTTPResponse()
                                .getHeaderMap()
                                .get("WWW-Authenticate")));
    }

    @Test
    void shouldReturn401ForAccessTokenThatIsAlreadyUsed() {
        String accessTokenAsString = UUID.randomUUID().toString();
        var accessToken = new BearerAccessToken(accessTokenAsString);
        boolean isNewAccount = true;
        addTokenToDynamoAndCreateAssociatedUser(
                accessTokenAsString, List.of(OIDCScopeValue.EMAIL.getValue()), isNewAccount);

        accessTokenStoreExtension.setAccessTokenStoreUsed(accessTokenAsString, true);

        var response =
                makeRequest(
                        Optional.empty(),
                        Map.of("Authorization", accessToken.toAuthorizationHeader()),
                        Map.of());

        assertThat(response, hasStatus(401));
        assertThat(
                response.getMultiValueHeaders().get("WWW-Authenticate"),
                equalTo(
                        new UserInfoErrorResponse(INVALID_TOKEN)
                                .toHTTPResponse()
                                .getHeaderMap()
                                .get("WWW-Authenticate")));

        assertTrue(accessTokenStoreExtension.getAccessToken(accessTokenAsString).get().isUsed());
    }

    @Test
    void shouldReturn401ForAccessTokenThatIsPastItsTtl() {
        String accessTokenAsString = UUID.randomUUID().toString();
        var accessToken = new BearerAccessToken(accessTokenAsString);
        boolean isNewAccount = true;
        addTokenToDynamoAndCreateAssociatedUser(
                accessTokenAsString, List.of(OIDCScopeValue.EMAIL.getValue()), isNewAccount);
        accessTokenStoreExtension.setAccessTokenTtlToZero(accessTokenAsString);

        var response =
                makeRequest(
                        Optional.empty(),
                        Map.of("Authorization", accessToken.toAuthorizationHeader()),
                        Map.of());

        assertThat(response, hasStatus(401));
        assertThat(
                response.getMultiValueHeaders().get("WWW-Authenticate"),
                equalTo(
                        new UserInfoErrorResponse(INVALID_TOKEN)
                                .toHTTPResponse()
                                .getHeaderMap()
                                .get("WWW-Authenticate")));
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

        userStore.signUp(EMAIL, PASSWORD, TEST_SUBJECT);
        userStore.addVerifiedPhoneNumber(EMAIL, UK_LANDLINE_NUMBER_NO_CC);
        return userStore.getUserProfileFromEmail(EMAIL).get();
    }
}
