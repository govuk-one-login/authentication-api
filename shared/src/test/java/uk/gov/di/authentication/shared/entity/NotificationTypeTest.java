package uk.gov.di.authentication.shared.entity;

import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.shared.entity.NotificationType.VERIFY_EMAIL;

class NotificationTypeTest {

    private final ConfigurationService configurationService = mock(ConfigurationService.class);

    @Test
    void shouldReturnDefaultTemplateForVerifyEmailWhenLanguageEN() {
        when(configurationService.getNotifyTemplateId("VERIFY_EMAIL_TEMPLATE_ID_CY"))
                .thenReturn("67890");
        when(configurationService.getNotifyTemplateId("VERIFY_EMAIL_TEMPLATE_ID"))
                .thenReturn("12345");
        assertThat(VERIFY_EMAIL.getTemplateId(configurationService), equalTo("12345"));
    }

    @Test
    void shouldReturnENTemplateForVerifyEmailWhenLanguageCYAndNotSingleTemplatePerLanguage() {
        when(configurationService.getNotifyTemplateId("VERIFY_EMAIL_TEMPLATE_ID_CY"))
                .thenReturn("67890");
        when(configurationService.getNotifyTemplateId("VERIFY_EMAIL_TEMPLATE_ID"))
                .thenReturn("12345");
        assertThat(VERIFY_EMAIL.getTemplateId(configurationService), equalTo("12345"));
    }

    @Test
    void shouldReturnDefaultTemplateForVerifyEmailWhenLanguageCYButTemplateMissing() {
        when(configurationService.getNotifyTemplateId("VERIFY_EMAIL_TEMPLATE_ID_CY"))
                .thenReturn("");
        when(configurationService.getNotifyTemplateId("VERIFY_EMAIL_TEMPLATE_ID"))
                .thenReturn("12345");
        assertThat(VERIFY_EMAIL.getTemplateId(configurationService), equalTo("12345"));
    }
}
