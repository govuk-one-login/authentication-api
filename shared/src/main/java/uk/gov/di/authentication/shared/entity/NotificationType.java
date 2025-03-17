package uk.gov.di.authentication.shared.entity;

import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.helpers.LocaleHelper.SupportedLanguage;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.util.HashMap;
import java.util.Map;

public enum NotificationType implements TemplateAware {
    VERIFY_EMAIL(
            "VERIFY_EMAIL_TEMPLATE_ID",
            Map.of(SupportedLanguage.CY, "VERIFY_EMAIL_TEMPLATE_ID_CY"),
            MFAMethodType.EMAIL,
            true),
    VERIFY_PHONE_NUMBER(
            "VERIFY_PHONE_NUMBER_TEMPLATE_ID",
            Map.of(SupportedLanguage.CY, "VERIFY_PHONE_NUMBER_TEMPLATE_ID_CY"),
            MFAMethodType.SMS,
            false),
    MFA_SMS(
            "MFA_SMS_TEMPLATE_ID",
            Map.of(SupportedLanguage.CY, "MFA_SMS_TEMPLATE_ID_CY"),
            MFAMethodType.SMS,
            false),
    PASSWORD_RESET_CONFIRMATION(
            "PASSWORD_RESET_CONFIRMATION_TEMPLATE_ID",
            Map.of(SupportedLanguage.CY, "PASSWORD_RESET_CONFIRMATION_TEMPLATE_ID_CY"),
            MFAMethodType.NONE,
            true),
    PASSWORD_RESET_CONFIRMATION_SMS(
            "PASSWORD_RESET_CONFIRMATION_SMS_TEMPLATE_ID",
            Map.of(SupportedLanguage.CY, "PASSWORD_RESET_CONFIRMATION_SMS_TEMPLATE_ID_CY"),
            MFAMethodType.NONE,
            false),
    ACCOUNT_CREATED_CONFIRMATION(
            "ACCOUNT_CREATED_CONFIRMATION_TEMPLATE_ID",
            Map.of(SupportedLanguage.CY, "ACCOUNT_CREATED_CONFIRMATION_TEMPLATE_ID_CY"),
            MFAMethodType.NONE,
            true),
    RESET_PASSWORD_WITH_CODE(
            "RESET_PASSWORD_WITH_CODE_TEMPLATE_ID",
            Map.of(SupportedLanguage.CY, "RESET_PASSWORD_WITH_CODE_TEMPLATE_ID_CY"),
            MFAMethodType.EMAIL,
            true),
    VERIFY_CHANGE_HOW_GET_SECURITY_CODES(
            "VERIFY_CHANGE_HOW_GET_SECURITY_CODES_TEMPLATE_ID",
            Map.of(SupportedLanguage.CY, "VERIFY_CHANGE_HOW_GET_SECURITY_CODES_TEMPLATE_ID_CY"),
            MFAMethodType.EMAIL,
            true),
    CHANGE_HOW_GET_SECURITY_CODES_CONFIRMATION(
            "CHANGE_HOW_GET_SECURITY_CODES_CONFIRMATION_TEMPLATE_ID",
            Map.of(
                    SupportedLanguage.CY,
                    "CHANGE_HOW_GET_SECURITY_CODES_CONFIRMATION_TEMPLATE_ID_CY"),
            MFAMethodType.NONE,
            true),
    TERMS_AND_CONDITIONS_BULK_EMAIL(
            "TERMS_AND_CONDITIONS_BULK_EMAIL_TEMPLATE_ID", MFAMethodType.NONE, true);

    private final String templateName;
    private final MFAMethodType mfaMethodType;
    private final boolean isEmail;

    private Map<SupportedLanguage, String> languageSpecificTemplates = new HashMap<>();

    NotificationType(String templateName, MFAMethodType mfaMethodType, boolean isEmail) {
        this.templateName = templateName;
        this.mfaMethodType = mfaMethodType;
        this.isEmail = isEmail;
    }

    NotificationType(
            String templateName,
            Map<SupportedLanguage, String> languageSpecificTemplates,
            MFAMethodType mfaMethodType,
            boolean isEmail) {
        this(templateName, mfaMethodType, isEmail);
        this.languageSpecificTemplates = languageSpecificTemplates;
    }

    public String getTemplateId(ConfigurationService configurationService) {
        return configurationService.getNotifyTemplateId(templateName);
    }

    String getTemplateName(SupportedLanguage language) {
        return languageSpecificTemplates.getOrDefault(language, templateName);
    }

    public MFAMethodType getMfaMethodType() {
        return mfaMethodType;
    }

    public boolean isEmail() {
        return isEmail;
    }
}
