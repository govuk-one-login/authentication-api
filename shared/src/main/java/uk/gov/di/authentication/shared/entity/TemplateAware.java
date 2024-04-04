package uk.gov.di.authentication.shared.entity;

import uk.gov.di.authentication.shared.services.ConfigurationService;

public interface TemplateAware {
    String getTemplateId(ConfigurationService configurationService);
}
