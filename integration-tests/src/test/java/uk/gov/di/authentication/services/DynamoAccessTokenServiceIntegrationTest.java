package uk.gov.di.authentication.services;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.authentication.shared.services.AccessTokenService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.sharedtest.extensions.AccessTokenStoreExtension;

import java.util.List;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;

public class DynamoAccessTokenServiceIntegrationTest {

    @RegisterExtension
    protected static final AccessTokenStoreExtension accessTokenStoreExtension =
            new AccessTokenStoreExtension(180);

    public static final String SUBJECT_ID_1 = "12345678";
    public static final String SUBJECT_ID_2 = "87654321";
    public static final String ACCESS_TOKEN_STRING = "access-token-string";
    public static final String ACCESS_TOKEN_STRING_2 = "access-token-string-2";
    public static final String ACCESS_TOKEN_STRING_3 = "access-token-string-3";

    AccessTokenService accessTokenService =
            new AccessTokenService(ConfigurationService.getInstance(), true);

    private void setUpDynamo() {
        accessTokenStoreExtension.addAccessTokenStore(
                ACCESS_TOKEN_STRING, SUBJECT_ID_1, List.of("scope1"));
        accessTokenStoreExtension.addAccessTokenStore(
                ACCESS_TOKEN_STRING_2, SUBJECT_ID_2, List.of("scope1", "scope2"));
        accessTokenStoreExtension.addAccessTokenStore(
                ACCESS_TOKEN_STRING_3, SUBJECT_ID_2, List.of("scope1", "scope2", "scope3"));
    }

    @Test
    void shouldRetrieveAccessTokenForKey() {
        setUpDynamo();

        var accessToken = accessTokenService.getAccessTokenStore(ACCESS_TOKEN_STRING);

        assertThat(accessToken.isPresent(), equalTo(true));
        accessToken.ifPresent(
                t -> {
                    assertThat(t.getAccessToken(), equalTo(ACCESS_TOKEN_STRING));
                    assertThat(t.getSubjectID(), equalTo(SUBJECT_ID_1));
                    assertThat(t.isUsed(), equalTo(false));
                    assertThat(t.getScopes(), equalTo(List.of("scope1")));
                });
    }

    @Test
    void shouldUpdateUsedFlag() {
        setUpDynamo();

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
}
