package uk.gov.di.authentication.shared.entity;

import uk.gov.di.authentication.shared.helpers.LocaleHelper.SupportedLanguage;

public interface TemplateAware {
    String getTemplateId();

    String getTemplateId(SupportedLanguage language);
}
