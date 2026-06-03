package uk.gov.di.orchestration.shared.utils;

import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import uk.gov.di.orchestration.shared.entity.ClientRegistry;

import java.util.Objects;

public class ClientUtils {
    private ClientUtils() {}

    public static String getTokenAuthMethodOrDefault(ClientRegistry clientRegistry) {
        var tokenAuthMethod = clientRegistry.getTokenAuthMethod();
        if (Objects.isNull(tokenAuthMethod)) {
            tokenAuthMethod = ClientAuthenticationMethod.PRIVATE_KEY_JWT.getValue();
        }
        return tokenAuthMethod;
    }
}
