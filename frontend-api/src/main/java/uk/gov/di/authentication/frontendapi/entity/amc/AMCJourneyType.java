package uk.gov.di.authentication.frontendapi.entity.amc;

import uk.gov.di.authentication.shared.entity.AccountDataScope;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.util.List;

public enum AMCJourneyType {
    SFAD,
    PASSKEY_CREATE;

    public List<AccessTokenConfig> getAccessTokenConfigs(ConfigurationService config) {
        return switch (this) {
            case SFAD -> List.of(
                    new AccessTokenConfig(
                            "account_management_api_access_token",
                            AccountManagementScope.ACCOUNT_DELETE,
                            config.getAuthToAMApiAudience(),
                            config.getAuthToAccountManagementSigningKey()));
            case PASSKEY_CREATE -> List.of(
                    new AccessTokenConfig(
                            "account_data_api_access_token",
                            AccountDataScope.PASSKEY_CREATE,
                            config.getAuthToAccountDataApiAudience(),
                            config.getAuthToAccountDataSigningKey()));
        };
    }

    public TransportJWTConfig getTransportJwtConfig(ConfigurationService config) {
        return switch (this) {
            case SFAD -> new TransportJWTConfig(
                    AMCScope.ACCOUNT_DELETE, config.getAMCSfadRedirectURI());
            case PASSKEY_CREATE -> new TransportJWTConfig(
                    AMCScope.PASSKEY_CREATE, config.getAMCCreatePasskeyRedirectURI());
        };
    }
}
