package uk.gov.di.orchestration.shared.entity;

import uk.gov.di.orchestration.shared.services.ConfigurationService;

public interface TemplateAware {
    String getTemplateId(ConfigurationService configurationService);
}
