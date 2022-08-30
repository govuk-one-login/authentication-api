package uk.gov.di.authentication.shared.entity;

import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.helpers.LocaleHelper.SupportedLanguage;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;

class NotificationTypeTest {

    @Test
    void shouldReturnDefaultTemplateForVerifyEmailWithLanguageEN() {
        assertThat(
                NotificationType.VERIFY_EMAIL.getTemplateName(SupportedLanguage.EN),
                equalTo("VERIFY_EMAIL_TEMPLATE_ID"));
    }

    @Test
    void shouldReturnWelshTemplateForVerifyEmailWithLanguageCY() {
        assertThat(
                NotificationType.VERIFY_EMAIL.getTemplateName(SupportedLanguage.CY),
                equalTo("VERIFY_EMAIL_TEMPLATE_ID_CY"));
    }

    @Test
    void shouldReturnDefaultTemplateForVerifyPhoneNumberWithLanguageEN() {
        assertThat(
                NotificationType.VERIFY_PHONE_NUMBER.getTemplateName(SupportedLanguage.EN),
                equalTo("VERIFY_PHONE_NUMBER_TEMPLATE_ID"));
    }

    @Test
    void shouldReturnWelshTemplateForVerifyPhoneNumberWithLanguageCY() {
        assertThat(
                NotificationType.VERIFY_PHONE_NUMBER.getTemplateName(SupportedLanguage.CY),
                equalTo("VERIFY_PHONE_NUMBER_TEMPLATE_ID_CY"));
    }
}
