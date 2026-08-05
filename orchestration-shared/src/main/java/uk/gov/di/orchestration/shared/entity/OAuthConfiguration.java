package uk.gov.di.orchestration.shared.entity;

import uk.gov.di.orchestration.shared.helpers.ConstructUriHelper;
import uk.gov.di.orchestration.shared.services.ConfigurationService;

import java.net.URI;

public record OAuthConfiguration(
        String clientId,
        URI authorizationURI,
        URI tokenURI,
        URI userInfoURI,
        URI redirectURI,
        String signingKeyAlias,
        String privateKeyJwtAudience,
        String statePrefix) {
    public static final String IPV_STATE_STORAGE_PREFIX = "state:";

    public static OAuthConfiguration getIPVConfig(ConfigurationService configurationService) {
        return new OAuthConfiguration(
                configurationService.getIPVAuthorisationClientId(),
                configurationService.getIPVAuthorisationURI(),
                ConstructUriHelper.buildURI(
                        configurationService.getIPVBackendURI().toString(), "token"),
                ConstructUriHelper.buildURI(
                        configurationService.getIPVBackendURI().toString(), "user-identity"),
                configurationService.getIPVAuthorisationCallbackURI(),
                configurationService.getIPVTokenSigningKeyAlias(),
                configurationService.getIPVAudience(),
                IPV_STATE_STORAGE_PREFIX);
    }
}
