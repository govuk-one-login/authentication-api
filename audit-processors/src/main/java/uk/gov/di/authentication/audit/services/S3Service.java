package uk.gov.di.authentication.audit.services;

import uk.gov.di.authentication.shared.services.ConfigurationService;

public class S3Service {
    private final ConfigurationService configurationService;

    public S3Service(ConfigurationService configurationService) {
        this.configurationService = configurationService;
    }
}
