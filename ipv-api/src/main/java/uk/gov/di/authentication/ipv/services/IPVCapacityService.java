package uk.gov.di.authentication.ipv.services;

import uk.gov.di.orchestration.shared.services.ConfigurationService;

public class IPVCapacityService {

    private final ConfigurationService configurationService;

    public IPVCapacityService(ConfigurationService configurationService) {
        this.configurationService = configurationService;
    }

    public boolean isIPVCapacityAvailable() {
        return configurationService.getIPVCapacity().map(c -> c.equals("1")).orElse(false);
    }
}
