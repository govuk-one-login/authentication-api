package uk.gov.di.authentication.shared.entity;

import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;

class NotificationTypeTest {

    @Test
    void shouldReturnDefaultTemplateForVerifyEmailWithLanguageEN() {
        assertThat(
                NotificationType.VERIFY_EMAIL.getTemplateName("en"),
                equalTo("VERIFY_EMAIL_TEMPLATE_ID"));
    }

    @Test
    void shouldReturnDefaultTemplateForVerifyEmailWithLanguageCY() {
        assertThat(
                NotificationType.VERIFY_EMAIL.getTemplateName("cy"),
                equalTo("VERIFY_EMAIL_TEMPLATE_ID_CY"));
    }

    /*
       TODO: This case is required but is not currently built
    */
    void shouldReturnDefaultTemplateForVerifyEmailWithLanguageCY_AR() {
        assertThat(
                NotificationType.VERIFY_EMAIL.getTemplateName("cy_AR"),
                equalTo("VERIFY_EMAIL_TEMPLATE_ID_CY"));
    }

    @Test
    void shouldReturnDefaultTemplateForVerifyPhoneNumberWithLanguageEN() {
        assertThat(
                NotificationType.VERIFY_PHONE_NUMBER.getTemplateName("en"),
                equalTo("VERIFY_PHONE_NUMBER_TEMPLATE_ID"));
    }

    @Test
    void shouldReturnDefaultTemplateForVerifyPhoneNumberWithLanguageCY() {
        assertThat(
                NotificationType.VERIFY_PHONE_NUMBER.getTemplateName("cy"),
                equalTo("VERIFY_PHONE_NUMBER_TEMPLATE_ID"));
    }
}
