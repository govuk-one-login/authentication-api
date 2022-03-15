package uk.gov.di.authentication.shared.entity;

public enum NotificationType implements TemplateAware {
    VERIFY_EMAIL("VERIFY_EMAIL_TEMPLATE_ID"),
    VERIFY_PHONE_NUMBER("VERIFY_PHONE_NUMBER_TEMPLATE_ID"),
    MFA_SMS("MFA_SMS_TEMPLATE_ID"),
    RESET_PASSWORD("RESET_PASSWORD_TEMPLATE_ID"),
    PASSWORD_RESET_CONFIRMATION("PASSWORD_RESET_CONFIRMATION_TEMPLATE_ID"),
    ACCOUNT_CREATED_CONFIRMATION("ACCOUNT_CREATED_CONFIRMATION_TEMPLATE_ID"),
    RESET_PASSWORD_WITH_CODE("RESET_PASSWORD_WITH_CODE_TEMPLATE_ID");

    private final String templateName;

    NotificationType(String templateName) {
        this.templateName = templateName;
    }

    public String getTemplateId() {
        return System.getenv(templateName);
    }
}
