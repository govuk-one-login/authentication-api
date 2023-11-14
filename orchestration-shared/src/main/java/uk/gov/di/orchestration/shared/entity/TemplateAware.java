package uk.gov.di.orchestration.shared.entity;

import uk.gov.di.orchestration.shared.helpers.LocaleHelper.SupportedLanguage;
import uk.gov.di.orchestration.shared.services.ConfigurationService;

public interface TemplateAware {
    String getTemplateId(SupportedLanguage language, ConfigurationService configurationService);
}
