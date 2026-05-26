package uk.gov.di.orchestration.shared.utils;

import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.orchestration.shared.entity.ClientRegistry;
import uk.gov.di.orchestration.shared.services.ConfigurationService;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class ClientUtilsTest {
    private final ConfigurationService configurationService = mock(ConfigurationService.class);

    @BeforeEach
    public void setup() {
        when(configurationService.isUseDefaultTokenAuthMethod()).thenReturn(false);
    }

    @Test
    void shouldDefaultToPrivateKeyJwtIfFeatureFlagIsEnabledAndTokenAuthMethodIsNull() {
        when(configurationService.isUseDefaultTokenAuthMethod()).thenReturn(true);
        var client = clientWithTokenAuthMethod(null);

        var actualTokenAuthMethod =
                ClientUtils.getTokenAuthMethodOrDefault(client, configurationService);
        assertEquals(actualTokenAuthMethod, ClientAuthenticationMethod.PRIVATE_KEY_JWT.getValue());
    }

    @Test
    void shouldNotDefaultToPrivateKeyJwtIfFeatureFlagDisabled() {
        when(configurationService.isUseDefaultTokenAuthMethod()).thenReturn(false);
        var client = clientWithTokenAuthMethod(null);

        var actualTokenAuthMethod =
                ClientUtils.getTokenAuthMethodOrDefault(client, configurationService);
        assertNull(actualTokenAuthMethod);
    }

    @Test
    void shouldNotDefaultToPrivateKeyJwtIfFeatureFlagIsEnabledAndTokenAuthMethodIsAlreadySet() {
        when(configurationService.isUseDefaultTokenAuthMethod()).thenReturn(true);
        var client =
                clientWithTokenAuthMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST.getValue());

        var actualTokenAuthMethod =
                ClientUtils.getTokenAuthMethodOrDefault(client, configurationService);
        assertEquals(
                actualTokenAuthMethod, ClientAuthenticationMethod.CLIENT_SECRET_POST.getValue());
    }

    private ClientRegistry clientWithTokenAuthMethod(String tokenAuthMethod) {
        return new ClientRegistry()
                .withClientID("client-id")
                .withClientName("client-one")
                .withTokenAuthMethod(tokenAuthMethod);
    }
}
