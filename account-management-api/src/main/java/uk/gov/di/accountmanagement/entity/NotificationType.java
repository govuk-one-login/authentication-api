package uk.gov.di.accountmanagement.entity;

import uk.gov.di.authentication.shared.entity.NotifiableType;
import uk.gov.di.authentication.shared.entity.TemplateAware;
import uk.gov.di.authentication.shared.services.ConfigurationService;

public enum NotificationType implements TemplateAware, NotifiableType {
    VERIFY_EMAIL("AM_VERIFY_EMAIL_TEMPLATE_ID", false),
    EMAIL_UPDATED("EMAIL_UPDATED_TEMPLATE_ID", false),
    DELETE_ACCOUNT("DELETE_ACCOUNT_TEMPLATE_ID", false),
    PHONE_NUMBER_UPDATED("PHONE_NUMBER_UPDATED_TEMPLATE_ID", false),
    VERIFY_PHONE_NUMBER("AM_VERIFY_PHONE_NUMBER_TEMPLATE_ID", true),
    PASSWORD_UPDATED("PASSWORD_UPDATED_TEMPLATE_ID", false),
    BACKUP_METHOD_ADDED("BACKUP_METHOD_ADDED_TEMPLATE_ID", false),
    BACKUP_METHOD_REMOVED("BACKUP_METHOD_REMOVED_TEMPLATE_ID", false),
    CHANGED_AUTHENTICATOR_APP("CHANGED_AUTHENTICATOR_APP_TEMPLATE_ID", false),
    CHANGED_DEFAULT_MFA("CHANGED_DEFAULT_MFA_TEMPLATE_ID", false),
    SWITCHED_MFA_METHODS("SWITCHED_MFA_METHODS_TEMPLATE_ID", false),
    PASSKEY_DELETED_NONE_REMAINING("PASSKEY_DELETED_TEMPLATE_ID", false),
    PASSKEY_DELETED_SOME_REMAINING("PASSKEY_DELETED_TEMPLATE_ID", false),
    ACCOUNT_DELETED_SELF_SERVICE("ACCOUNT_DELETED_SELF_SERVICE_TEMPLATE_ID", false),
    ;

    private final String templateName;
    private final boolean isForPhoneNumber;

    NotificationType(String templateName, boolean isForPhoneNumber) {
        this.templateName = templateName;
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
}
