package uk.gov.di.orchestration.shared.utils;

import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import org.junit.jupiter.api.Test;
import uk.gov.di.orchestration.shared.entity.ClientRegistry;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class ClientUtilsTest {

    @Test
    void shouldDefaultToPrivateKeyJwtIfFeatureFlagIsEnabledAndTokenAuthMethodIsNull() {
        var client = clientWithTokenAuthMethod(null);

        var actualTokenAuthMethod = ClientUtils.getTokenAuthMethodOrDefault(client);
        assertEquals(actualTokenAuthMethod, ClientAuthenticationMethod.PRIVATE_KEY_JWT.getValue());
    }

    @Test
    void shouldNotDefaultToPrivateKeyJwtIfFeatureFlagIsEnabledAndTokenAuthMethodIsAlreadySet() {
        var client =
                clientWithTokenAuthMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST.getValue());

        var actualTokenAuthMethod = ClientUtils.getTokenAuthMethodOrDefault(client);
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
