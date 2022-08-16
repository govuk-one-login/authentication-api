package uk.gov.di.authentication.shared.entity;

import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

public enum NotificationType implements TemplateAware {
    VERIFY_EMAIL(
            "VERIFY_EMAIL_TEMPLATE_ID",
            Map.of(Locale.forLanguageTag("cy"), "VERIFY_EMAIL_TEMPLATE_ID_CY")),
    VERIFY_PHONE_NUMBER("VERIFY_PHONE_NUMBER_TEMPLATE_ID"),
    MFA_SMS("MFA_SMS_TEMPLATE_ID"),
    RESET_PASSWORD("RESET_PASSWORD_TEMPLATE_ID"),
    PASSWORD_RESET_CONFIRMATION("PASSWORD_RESET_CONFIRMATION_TEMPLATE_ID"),
    ACCOUNT_CREATED_CONFIRMATION("ACCOUNT_CREATED_CONFIRMATION_TEMPLATE_ID"),
    RESET_PASSWORD_WITH_CODE("RESET_PASSWORD_WITH_CODE_TEMPLATE_ID");

    private final String templateName;

    private static final ConfigurationService configurationService = new ConfigurationService();
    private Map<Locale, String> languageSpecificTemplates = new HashMap<>();

    private NotificationType(String templateName) {
        this.templateName = templateName;
    }

    private NotificationType(String templateName, Map<Locale, String> languageSpecificTemplates) {
        this(templateName);
        this.languageSpecificTemplates = languageSpecificTemplates;
    }

    public String getTemplateId() {
        return System.getenv(templateName);
    }

    public String getTemplateId(String language) {
        return configurationService.getNotifyTemplateId(getTemplateName(language));
    }

    String getTemplateName(String language) {
        Locale locale = Locale.forLanguageTag(language);
        if (languageSpecificTemplates.containsKey(locale)) {
            return languageSpecificTemplates.get(locale);
        } else {
            return templateName;
        }
    }
}
