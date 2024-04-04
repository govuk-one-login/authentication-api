package uk.gov.di.accountmanagement.entity;

import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.helpers.LocaleHelper.SupportedLanguage;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.accountmanagement.entity.NotificationType.DELETE_ACCOUNT;
import static uk.gov.di.accountmanagement.entity.NotificationType.VERIFY_EMAIL;

class NotificationTypeTest {

    private final ConfigurationService configurationService = mock(ConfigurationService.class);

    @Test
    void shouldReturnDefaultTemplateForVerifyEmailWhenLanguageEN() {
        when(configurationService.getNotifyTemplateId("AM_VERIFY_EMAIL_TEMPLATE_ID_CY"))
                .thenReturn("67890");
        when(configurationService.getNotifyTemplateId("AM_VERIFY_EMAIL_TEMPLATE_ID"))
                .thenReturn("12345");
        assertThat(
                VERIFY_EMAIL.getTemplateId(SupportedLanguage.EN, configurationService),
                equalTo("12345"));
    }

    @Test
    void shouldReturnDefaultTemplateForVerifyEmailWhenLanguageCYAndNotSingleTemplatePerLanguage() {
        when(configurationService.getNotifyTemplateId("AM_VERIFY_EMAIL_TEMPLATE_ID_CY"))
                .thenReturn("67890");
        when(configurationService.getNotifyTemplateId("AM_VERIFY_EMAIL_TEMPLATE_ID"))
                .thenReturn("12345");
        assertThat(
                VERIFY_EMAIL.getTemplateId(SupportedLanguage.CY, configurationService),
                equalTo("12345"));
    }

    @Test
    void
            shouldReturnDefaultTemplateForDeleteAccountWhenLanguageCYAndNotSingleTemplatePerLanguage() {
        when(configurationService.getNotifyTemplateId("DELETE_ACCOUNT_TEMPLATE_ID_CY"))
                .thenReturn("67890");
        when(configurationService.getNotifyTemplateId("DELETE_ACCOUNT_TEMPLATE_ID"))
                .thenReturn("12345");
        assertThat(
                DELETE_ACCOUNT.getTemplateId(SupportedLanguage.CY, configurationService),
                equalTo("12345"));
    }

    @Test
    void shouldReturnDefaultTemplateForVerifyEmailWhenLanguageCYButTemplateMissing() {
        when(configurationService.getNotifyTemplateId("AM_VERIFY_EMAIL_TEMPLATE_ID_CY"))
                .thenReturn("");
        when(configurationService.getNotifyTemplateId("AM_VERIFY_EMAIL_TEMPLATE_ID"))
                .thenReturn("12345");
        assertThat(
                VERIFY_EMAIL.getTemplateId(SupportedLanguage.CY, configurationService),
                equalTo("12345"));
    }
}
