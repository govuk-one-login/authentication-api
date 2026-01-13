package uk.gov.di.authentication.frontendapi.services.webauthn;

import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.data.RelyingPartyIdentity;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.util.HashMap;
import java.util.Map;

public class RelyingPartyProvider {

    private static final Map<ConfigurationService, RelyingParty> instances = new HashMap<>();

    public static synchronized RelyingParty provide(ConfigurationService configurationService) {
        return instances.computeIfAbsent(
                configurationService,
                config -> {
                    RelyingPartyIdentity rpIdentity =
                            RelyingPartyIdentity.builder()
                                    .id(config.getWebAuthnRelyingPartyId())
                                    .name(config.getWebAuthnRelyingPartyName())
                                    .build();

                    InMemoryCredentialRepository credentialRepository =
                            new InMemoryCredentialRepository();

                    return RelyingParty.builder()
                            .identity(rpIdentity)
                            .credentialRepository(credentialRepository)
                            .build();
                });
    }
}
