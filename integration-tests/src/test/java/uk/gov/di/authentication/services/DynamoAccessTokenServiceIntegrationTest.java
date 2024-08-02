package uk.gov.di.authentication.services;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.authentication.shared.services.AccessTokenService;
import uk.gov.di.authentication.sharedtest.basetest.ApiGatewayHandlerIntegrationTest;
import uk.gov.di.authentication.sharedtest.extensions.AccessTokenStoreExtension;

import java.util.List;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class DynamoAccessTokenServiceIntegrationTest extends ApiGatewayHandlerIntegrationTest {

    @RegisterExtension
    protected static final AccessTokenStoreExtension accessTokenStoreExtension =
            new AccessTokenStoreExtension(180);

    public static final String SUBJECT_ID_1 = "12345678";
    public static final String SUBJECT_ID_2 = "87654321";
    public static final String ACCESS_TOKEN_STRING = "access-token-string";
    public static final String ACCESS_TOKEN_STRING_2 = "access-token-string-2";
    public static final String ACCESS_TOKEN_STRING_3 = "access-token-string-3";
    public static final String ACCESS_TOKEN_STRING_4 = "access-token-string-4";
    private static final Long PASSWORD_RESET_TIME = 1696869005821L;

    AccessTokenService accessTokenService = new AccessTokenService(TEST_CONFIGURATION_SERVICE);

    @Test
    void shouldRetrieveAccessTokenForKey() {
        accessTokenStoreExtension.addAccessTokenStore(
                ACCESS_TOKEN_STRING, SUBJECT_ID_1, List.of("scope1"));

        var accessToken = accessTokenService.getAccessTokenStore(ACCESS_TOKEN_STRING);

        assertThat(accessToken.isPresent(), equalTo(true));
        accessToken.ifPresent(
                t -> {
                    assertThat(t.getAccessToken(), equalTo(ACCESS_TOKEN_STRING));
                    assertThat(t.getSubjectID(), equalTo(SUBJECT_ID_1));
                    assertThat(t.isUsed(), equalTo(false));
                    assertThat(t.getClaims(), equalTo(List.of("scope1")));
                    assertThat(t.getPasswordResetTime(), equalTo(null));
                });
    }

    @Test
    void shouldUpdateUsedFlag() {
        accessTokenStoreExtension.addAccessTokenStore(
                ACCESS_TOKEN_STRING_2, SUBJECT_ID_2, List.of("scope1", "scope2"));

        var accessToken = accessTokenService.getAccessTokenStore(ACCESS_TOKEN_STRING_2);
        assertThat(accessToken.isPresent(), equalTo(true));
        accessToken.ifPresent(
                t -> {
                    assertThat(t.isUsed(), equalTo(false));
                });
        accessToken = accessTokenService.setAccessTokenStoreUsed(ACCESS_TOKEN_STRING_2, true);
        assertThat(accessToken.isPresent(), equalTo(true));

        var updatedAccessToken = accessTokenService.getAccessTokenStore(ACCESS_TOKEN_STRING_2);
        assertThat(updatedAccessToken.isPresent(), equalTo(true));
        updatedAccessToken.ifPresent(
                t -> {
                    assertThat(t.isUsed(), equalTo(true));
                });
    }

    @Test
    void shouldUpdateTtl() {
        accessTokenStoreExtension.addAccessTokenStore(
                ACCESS_TOKEN_STRING_3, SUBJECT_ID_2, List.of("scope1", "scope2", "scope3"));

        var accessToken = accessTokenService.getAccessTokenStore(ACCESS_TOKEN_STRING_3);
        assertThat(accessToken.isPresent(), equalTo(true));

        long newTtl = 4090552069L;
        accessToken = accessTokenService.setAccessTokenTtlTestOnly(ACCESS_TOKEN_STRING_3, newTtl);
        assertThat(accessToken.isPresent(), equalTo(true));

        var updatedAccessToken = accessTokenService.getAccessTokenStore(ACCESS_TOKEN_STRING_3);
        assertThat(updatedAccessToken.isPresent(), equalTo(true));
        updatedAccessToken.ifPresent(
                t -> {
                    assertThat(t.getTimeToExist(), equalTo(newTtl));
                });
    }

    @Test
    void shouldStoreAndRetrieveAnAccessTokenWithAPasswordResetTime() {
        accessTokenStoreExtension.addAccessTokenStore(ACCESS_TOKEN_STRING_4, PASSWORD_RESET_TIME);

        var accessToken = accessTokenService.getAccessTokenStore(ACCESS_TOKEN_STRING_4).get();

        assertEquals(PASSWORD_RESET_TIME, accessToken.getPasswordResetTime());
    }
}
