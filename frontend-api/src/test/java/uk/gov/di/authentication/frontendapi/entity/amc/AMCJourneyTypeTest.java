package uk.gov.di.authentication.frontendapi.entity.amc;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.entity.AccountDataScope;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AMCJourneyTypeTest {

    private static final String ACCOUNT_DATA_API_AUDIENCE = "https://example.com/ADAPIAudience";
    private static final String ACCOUNT_DATA_SIGNING_KEY = "account-data-signing-key";

    private final ConfigurationService configurationService = mock(ConfigurationService.class);

    @BeforeEach
    void setup() {
        when(configurationService.getAuthToAccountDataApiAudience())
                .thenReturn(ACCOUNT_DATA_API_AUDIENCE);
        when(configurationService.getAuthToAccountDataSigningKey())
                .thenReturn(ACCOUNT_DATA_SIGNING_KEY);
    }

    @Test
    void shouldSendAnAccountDataApiAccessTokenForSsad() {
        var accessTokenConfigs = AMCJourneyType.SSAD.getAccessTokenConfigs(configurationService);

        assertEquals(
                List.of(
                        new AccessTokenConfig(
                                "account_data_api_access_token",
                                List.of(
                                        AccountDataScope.ACCOUNT_DELETE,
                                        AccountDataScope.VERIFY_PASSWORD),
                                ACCOUNT_DATA_API_AUDIENCE,
                                ACCOUNT_DATA_SIGNING_KEY,
                                30L)),
                accessTokenConfigs);
    }

    @Test
    void shouldSendAnAccountDataApiAccessTokenWithPasskeyScopesForPasskeyCreate() {
        var accessTokenConfigs =
                AMCJourneyType.PASSKEY_CREATE.getAccessTokenConfigs(configurationService);

        assertEquals(
                List.of(
                        new AccessTokenConfig(
                                "account_data_api_access_token",
                                List.of(
                                        AccountDataScope.PASSKEY_CREATE,
                                        AccountDataScope.PASSKEY_RETRIEVE),
                                ACCOUNT_DATA_API_AUDIENCE,
                                ACCOUNT_DATA_SIGNING_KEY,
                                5L)),
                accessTokenConfigs);
    }
}
