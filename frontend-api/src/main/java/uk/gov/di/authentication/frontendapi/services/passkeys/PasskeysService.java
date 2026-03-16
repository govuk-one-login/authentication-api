package uk.gov.di.authentication.shared.services.passkeys;

import uk.gov.di.authentication.shared.services.ConfigurationService;

public class PasskeysService {
    private final ConfigurationService configurationService;
    public PasskeysService(ConfigurationService configurationService) {
        this.configurationService = configurationService;
    }

    public boolean hasActivePasskey(String publicSubjectId) {
        return false;
    }
}
