package uk.gov.di.authentication.shared.entity;

import uk.gov.di.authentication.shared.helpers.LocaleHelper.SupportedLanguage;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.util.HashMap;
import java.util.Map;

public enum NotificationType implements TemplateAware {
    VERIFY_EMAIL(
            "VERIFY_EMAIL_TEMPLATE_ID",
            Map.of(SupportedLanguage.CY, "VERIFY_EMAIL_TEMPLATE_ID_CY")),
    VERIFY_PHONE_NUMBER(
            "VERIFY_PHONE_NUMBER_TEMPLATE_ID",
            Map.of(SupportedLanguage.CY, "VERIFY_PHONE_NUMBER_TEMPLATE_ID_CY")),
    MFA_SMS("MFA_SMS_TEMPLATE_ID", Map.of(SupportedLanguage.CY, "MFA_SMS_TEMPLATE_ID_CY")),
    RESET_PASSWORD(
            "RESET_PASSWORD_TEMPLATE_ID",
            Map.of(SupportedLanguage.CY, "RESET_PASSWORD_TEMPLATE_ID_CY")),
    PASSWORD_RESET_CONFIRMATION(
            "PASSWORD_RESET_CONFIRMATION_TEMPLATE_ID",
            Map.of(SupportedLanguage.CY, "PASSWORD_RESET_CONFIRMATION_TEMPLATE_ID_CY")),
    ACCOUNT_CREATED_CONFIRMATION(
            "ACCOUNT_CREATED_CONFIRMATION_TEMPLATE_ID",
            Map.of(SupportedLanguage.CY, "ACCOUNT_CREATED_CONFIRMATION_TEMPLATE_ID_CY")),
    RESET_PASSWORD_WITH_CODE(
            "RESET_PASSWORD_WITH_CODE_TEMPLATE_ID",
            Map.of(SupportedLanguage.CY, "RESET_PASSWORD_WITH_CODE_TEMPLATE_ID_CY"));

    private final String templateName;

    private Map<SupportedLanguage, String> languageSpecificTemplates = new HashMap<>();

    private NotificationType(String templateName) {
        this.templateName = templateName;
    }

    private NotificationType(
            String templateName, Map<SupportedLanguage, String> languageSpecificTemplates) {
        this(templateName);
        this.languageSpecificTemplates = languageSpecificTemplates;
    }

    public String getTemplateId() {
        return System.getenv(templateName);
    }

    public String getTemplateId(
            SupportedLanguage language, ConfigurationService configurationService) {
        String templateId = configurationService.getNotifyTemplateId(getTemplateName(language));
        if (templateId == null || templateId.length() == 0) {
            return configurationService.getNotifyTemplateId(templateName);
        } else {
            return templateId;
        }
    }

    String getTemplateName(SupportedLanguage language) {
        if (languageSpecificTemplates.containsKey(language)) {
            return languageSpecificTemplates.get(language);
        } else {
            return templateName;
        }
    }
}
