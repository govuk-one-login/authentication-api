package uk.gov.di.accountmanagement.entity;

import uk.gov.di.authentication.shared.entity.NotifiableType;
import uk.gov.di.authentication.shared.entity.TemplateAware;
import uk.gov.di.authentication.shared.helpers.LocaleHelper.SupportedLanguage;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.util.EnumMap;
import java.util.Map;

public enum NotificationType implements TemplateAware, NotifiableType {
    VERIFY_EMAIL(
            "AM_VERIFY_EMAIL_TEMPLATE_ID",
            new EnumMap<>(Map.of(SupportedLanguage.CY, "AM_VERIFY_EMAIL_TEMPLATE_ID_CY")),
            false),
    EMAIL_UPDATED(
            "EMAIL_UPDATED_TEMPLATE_ID",
            new EnumMap<>(Map.of(SupportedLanguage.CY, "EMAIL_UPDATED_TEMPLATE_ID_CY")),
            false),
    DELETE_ACCOUNT(
            "DELETE_ACCOUNT_TEMPLATE_ID",
            new EnumMap<>(Map.of(SupportedLanguage.CY, "DELETE_ACCOUNT_TEMPLATE_ID_CY")),
            false),
    PHONE_NUMBER_UPDATED(
            "PHONE_NUMBER_UPDATED_TEMPLATE_ID",
            new EnumMap<>(Map.of(SupportedLanguage.CY, "PHONE_NUMBER_UPDATED_TEMPLATE_ID_CY")),
            false),
    VERIFY_PHONE_NUMBER(
            "AM_VERIFY_PHONE_NUMBER_TEMPLATE_ID",
            new EnumMap<>(Map.of(SupportedLanguage.CY, "AM_VERIFY_PHONE_NUMBER_TEMPLATE_ID_CY")),
            true),
    PASSWORD_UPDATED(
            "PASSWORD_UPDATED_TEMPLATE_ID",
            new EnumMap<>(Map.of(SupportedLanguage.CY, "PASSWORD_UPDATED_TEMPLATE_ID_CY")),
            false),
    BACKUP_METHOD_ADDED(
            "BACKUP_METHOD_ADDED_TEMPLATE_ID",
            new EnumMap<>(Map.of(SupportedLanguage.CY, "BACKUP_METHOD_ADDED_TEMPLATE_ID_CY")),
            false),
    BACKUP_METHOD_REMOVED(
            "BACKUP_METHOD_REMOVED_TEMPLATE_ID",
            new EnumMap<>(Map.of(SupportedLanguage.CY, "BACKUP_METHOD_REMOVED_TEMPLATE_ID_CY")),
            false),
    CHANGED_AUTHENTICATOR_APP(
            "CHANGED_AUTHENTICATOR_APP_TEMPLATE_ID",
            new EnumMap<>(Map.of(SupportedLanguage.CY, "CHANGED_AUTHENTICATOR_APP_TEMPLATE_ID_CY")),
            false),
    CHANGED_DEFAULT_MFA(
            "CHANGED_DEFAULT_MFA_TEMPLATE_ID",
            new EnumMap<>(Map.of(SupportedLanguage.CY, "CHANGED_DEFAULT_MFA_TEMPLATE_ID_CY")),
            false),
    SWITCHED_MFA_METHODS(
            "SWITCHED_MFA_METHODS_TEMPLATE_ID",
            new EnumMap<>(Map.of(SupportedLanguage.CY, "SWITCHED_MFA_METHODS_TEMPLATE_ID_CY")),
            false),
    ;

    private final String templateName;
    private final boolean isForPhoneNumber;

    private EnumMap<SupportedLanguage, String> languageSpecificTemplates =
            new EnumMap<>(SupportedLanguage.class);

    NotificationType(
            String templateName,
            EnumMap<SupportedLanguage, String> languageSpecificTemplates,
            boolean isForPhoneNumber) {
        this.templateName = templateName;
        this.languageSpecificTemplates = languageSpecificTemplates;
        this.isForPhoneNumber = isForPhoneNumber;
    }

    @Override
    public String getTemplateId(ConfigurationService configurationService) {
        return configurationService.getNotifyTemplateId(templateName);
    }

    @Override
    public boolean isForPhoneNumber() {
        return isForPhoneNumber;
    }

    String getTemplateName(SupportedLanguage language) {
        return languageSpecificTemplates.getOrDefault(language, templateName);
    }
}
