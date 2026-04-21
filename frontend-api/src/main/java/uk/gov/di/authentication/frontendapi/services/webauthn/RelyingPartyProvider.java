package uk.gov.di.authentication.frontendapi.services.webauthn;

import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.data.RelyingPartyIdentity;
import uk.gov.di.authentication.frontendapi.services.passkeys.PasskeysService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;

import java.util.HashMap;
import java.util.Map;

public class RelyingPartyProvider {

    private static final Map<ConfigurationService, RelyingParty> instances = new HashMap<>();

    public static synchronized RelyingParty provide(ConfigurationService configurationService) {
        return provide(
                configurationService,
                new PasskeysService(configurationService),
                new DynamoService(configurationService));
    }

    public static synchronized RelyingParty provide(
            ConfigurationService configurationService,
            PasskeysService passkeysService,
            AuthenticationService authenticationService) {
        return instances.computeIfAbsent(
                configurationService,
                config -> {
                    RelyingPartyIdentity rpIdentity =
                            RelyingPartyIdentity.builder()
                                    .id(config.getWebAuthnRelyingPartyId())
                                    .name(config.getWebAuthnRelyingPartyName())
                                    .build();

                    AccountDataCredentialRepository credentialRepository =
                            new AccountDataCredentialRepository(
                                    passkeysService, authenticationService, configurationService);

                    return RelyingParty.builder()
                            .identity(rpIdentity)
                            .credentialRepository(credentialRepository)
                            .build();
                });
    }
}
