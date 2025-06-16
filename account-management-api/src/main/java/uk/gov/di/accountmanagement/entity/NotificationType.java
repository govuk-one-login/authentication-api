package uk.gov.di.accountmanagement.entity;

import uk.gov.di.authentication.shared.entity.TemplateAware;
import uk.gov.di.authentication.shared.helpers.LocaleHelper.SupportedLanguage;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.util.EnumMap;
import java.util.Map;

public enum NotificationType implements TemplateAware {
    VERIFY_EMAIL(
            "AM_VERIFY_EMAIL_TEMPLATE_ID",
            new EnumMap<>(Map.of(SupportedLanguage.CY, "AM_VERIFY_EMAIL_TEMPLATE_ID_CY"))),
    EMAIL_UPDATED(
            "EMAIL_UPDATED_TEMPLATE_ID",
            new EnumMap<>(Map.of(SupportedLanguage.CY, "EMAIL_UPDATED_TEMPLATE_ID_CY"))),
    DELETE_ACCOUNT(
            "DELETE_ACCOUNT_TEMPLATE_ID",
            new EnumMap<>(Map.of(SupportedLanguage.CY, "DELETE_ACCOUNT_TEMPLATE_ID_CY"))),
    PHONE_NUMBER_UPDATED(
            "PHONE_NUMBER_UPDATED_TEMPLATE_ID",
            new EnumMap<>(Map.of(SupportedLanguage.CY, "PHONE_NUMBER_UPDATED_TEMPLATE_ID_CY"))),
    VERIFY_PHONE_NUMBER(
            "AM_VERIFY_PHONE_NUMBER_TEMPLATE_ID",
            new EnumMap<>(Map.of(SupportedLanguage.CY, "AM_VERIFY_PHONE_NUMBER_TEMPLATE_ID_CY"))),
    PASSWORD_UPDATED(
            "PASSWORD_UPDATED_TEMPLATE_ID",
            new EnumMap<>(Map.of(SupportedLanguage.CY, "PASSWORD_UPDATED_TEMPLATE_ID_CY"))),
    BACKUP_METHOD_ADDED(
            "BACKUP_METHOD_ADDED_TEMPLATE_ID",
            new EnumMap<>(Map.of(SupportedLanguage.CY, "BACKUP_METHOD_ADDED_TEMPLATE_ID_CY"))),
    BACKUP_METHOD_REMOVED(
            "BACKUP_METHOD_REMOVED_TEMPLATE_ID",
            new EnumMap<>(Map.of(SupportedLanguage.CY, "BACKUP_METHOD_REMOVED_TEMPLATE_ID_CY")));

    private final String templateName;

    private EnumMap<SupportedLanguage, String> languageSpecificTemplates =
            new EnumMap<>(SupportedLanguage.class);

    NotificationType(String templateName) {
        this.templateName = templateName;
    }

    NotificationType(
            String templateName, EnumMap<SupportedLanguage, String> languageSpecificTemplates) {
        this(templateName);
        this.languageSpecificTemplates = languageSpecificTemplates;
    }

    @Override
    public String getTemplateId(ConfigurationService configurationService) {
        return configurationService.getNotifyTemplateId(templateName);
    }

    String getTemplateName(SupportedLanguage language) {
        return languageSpecificTemplates.getOrDefault(language, templateName);
    }
}
