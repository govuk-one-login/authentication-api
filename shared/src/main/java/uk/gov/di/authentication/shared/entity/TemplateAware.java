package uk.gov.di.authentication.shared.entity;

import uk.gov.di.authentication.shared.helpers.LocaleHelper.SupportedLanguage;
import uk.gov.di.authentication.shared.services.ConfigurationService;

public interface TemplateAware {
    String getTemplateId();

    String getTemplateId(SupportedLanguage language, ConfigurationService configurationService);
}
