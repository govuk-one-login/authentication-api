package uk.gov.di.authentication.ipv.services;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.shared.services.ConfigurationService;

public class IPVCapacityService {

    private static final Logger LOG = LogManager.getLogger(IPVCapacityService.class);
    private final ConfigurationService configurationService;

    public IPVCapacityService(ConfigurationService configurationService) {
        this.configurationService = configurationService;
    }

    public boolean isIPVCapacityAvailable() {
        return configurationService.getIPVCapacity().map(c -> c.equals("1")).orElse(false);
    }
}
