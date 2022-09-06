package uk.gov.di.accountmanagement.services;

import org.junit.jupiter.api.Test;
import uk.gov.di.accountmanagement.entity.NotificationType;
import uk.gov.di.authentication.shared.helpers.LocaleHelper.SupportedLanguage;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.service.notify.NotificationClient;
import uk.gov.service.notify.NotificationClientException;

import java.util.HashMap;
import java.util.Map;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class NotificationServiceTest {

    private static final String TEST_EMAIL = "test@digital.cabinet-office.gov.uk";
    private static final String TEST_PHONE_NUMBER = "01234567890";
    private final NotificationClient notificationClient = mock(NotificationClient.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final NotificationService notificationService =
            new NotificationService(notificationClient, configurationService);

    @Test
    void shouldCallNotifyClientToSendEmail() throws NotificationClientException {
        when(configurationService.getNotifyTemplateId("EMAIL_UPDATED_TEMPLATE_ID"))
                .thenReturn("123456");
        Map<String, Object> emailPersonalisation = new HashMap<>();
        emailPersonalisation.put("validation-code", "some-code");
        emailPersonalisation.put("email-address", TEST_EMAIL);

        notificationService.sendEmail(
                TEST_EMAIL,
                emailPersonalisation,
                NotificationType.EMAIL_UPDATED,
                SupportedLanguage.EN);

        verify(notificationClient).sendEmail("123456", TEST_EMAIL, emailPersonalisation, "");
    }

    @Test
    void shouldCallNotifyClientToSendText() throws NotificationClientException {
        when(configurationService.getNotifyTemplateId("PHONE_NUMBER_UPDATED_TEMPLATE_ID"))
                .thenReturn("567890");
        Map<String, Object> phonePersonalisation = new HashMap<>();
        phonePersonalisation.put("validation-code", "some-code");
        notificationService.sendText(
                TEST_PHONE_NUMBER,
                phonePersonalisation,
                NotificationType.PHONE_NUMBER_UPDATED,
                SupportedLanguage.EN);

        verify(notificationClient).sendSms("567890", TEST_PHONE_NUMBER, phonePersonalisation, "");
    }
}
