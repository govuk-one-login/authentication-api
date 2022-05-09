package uk.gov.di.authentication.oidc.services;

import uk.gov.di.authentication.shared.services.ConfigurationService;

public class IPVCapacityService {

    private final ConfigurationService configurationService;

    public IPVCapacityService(ConfigurationService configurationService) {
        this.configurationService = configurationService;
    }

    public boolean isIPVCapacityAvailable() {
        return configurationService.getIPVCapacity().map(c -> c.equals("1")).orElse(false);
    }
}
