package uk.gov.di.authentication.shared.entity;

import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.helpers.LocaleHelper.SupportedLanguage;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.util.HashMap;
import java.util.Map;

public enum NotificationType implements TemplateAware, NotifiableType {
    VERIFY_EMAIL(
            "VERIFY_EMAIL_TEMPLATE_ID",
            Map.of(SupportedLanguage.CY, "VERIFY_EMAIL_TEMPLATE_ID_CY"),
            MFAMethodType.EMAIL,
            true,
            false),
    VERIFY_PHONE_NUMBER(
            "VERIFY_PHONE_NUMBER_TEMPLATE_ID",
            Map.of(SupportedLanguage.CY, "VERIFY_PHONE_NUMBER_TEMPLATE_ID_CY"),
            MFAMethodType.SMS,
            false,
            true),
    MFA_SMS(
            "MFA_SMS_TEMPLATE_ID",
            Map.of(SupportedLanguage.CY, "MFA_SMS_TEMPLATE_ID_CY"),
            MFAMethodType.SMS,
            false,
            true),
    PASSWORD_RESET_CONFIRMATION(
            "PASSWORD_RESET_CONFIRMATION_TEMPLATE_ID",
            Map.of(SupportedLanguage.CY, "PASSWORD_RESET_CONFIRMATION_TEMPLATE_ID_CY"),
            MFAMethodType.NONE,
            true,
            false),
    PASSWORD_RESET_CONFIRMATION_SMS(
            "PASSWORD_RESET_CONFIRMATION_SMS_TEMPLATE_ID",
            Map.of(SupportedLanguage.CY, "PASSWORD_RESET_CONFIRMATION_SMS_TEMPLATE_ID_CY"),
            MFAMethodType.NONE,
            false,
            true),
    ACCOUNT_CREATED_CONFIRMATION(
            "ACCOUNT_CREATED_CONFIRMATION_TEMPLATE_ID",
            Map.of(SupportedLanguage.CY, "ACCOUNT_CREATED_CONFIRMATION_TEMPLATE_ID_CY"),
            MFAMethodType.NONE,
            true,
            false),
    RESET_PASSWORD_WITH_CODE(
            "RESET_PASSWORD_WITH_CODE_TEMPLATE_ID",
            Map.of(SupportedLanguage.CY, "RESET_PASSWORD_WITH_CODE_TEMPLATE_ID_CY"),
            MFAMethodType.EMAIL,
            true,
            false),
    VERIFY_CHANGE_HOW_GET_SECURITY_CODES(
            "VERIFY_CHANGE_HOW_GET_SECURITY_CODES_TEMPLATE_ID",
            Map.of(SupportedLanguage.CY, "VERIFY_CHANGE_HOW_GET_SECURITY_CODES_TEMPLATE_ID_CY"),
            MFAMethodType.EMAIL,
            true,
            false),
    CHANGE_HOW_GET_SECURITY_CODES_CONFIRMATION(
            "CHANGE_HOW_GET_SECURITY_CODES_CONFIRMATION_TEMPLATE_ID",
            Map.of(
                    SupportedLanguage.CY,
                    "CHANGE_HOW_GET_SECURITY_CODES_CONFIRMATION_TEMPLATE_ID_CY"),
            MFAMethodType.NONE,
            true,
            false),
    TERMS_AND_CONDITIONS_BULK_EMAIL(
            "TERMS_AND_CONDITIONS_BULK_EMAIL_TEMPLATE_ID", MFAMethodType.NONE, true, false);

    private final String templateName;
    private final MFAMethodType mfaMethodType;
    private final boolean isEmail;
    private final boolean isForPhoneNumber;

    private Map<SupportedLanguage, String> languageSpecificTemplates = new HashMap<>();

    NotificationType(
            String templateName,
            MFAMethodType mfaMethodType,
            boolean isEmail,
            boolean isForPhoneNumber) {
        this.templateName = templateName;
        this.mfaMethodType = mfaMethodType;
        this.isEmail = isEmail;
        this.isForPhoneNumber = isForPhoneNumber;
    }

    NotificationType(
            String templateName,
            Map<SupportedLanguage, String> languageSpecificTemplates,
            MFAMethodType mfaMethodType,
            boolean isEmail,
            boolean isForPhoneNumber) {
        this(templateName, mfaMethodType, isEmail, isForPhoneNumber);
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

    @Override
    public boolean isForPhoneNumber() {
        return isForPhoneNumber;
    }
}
