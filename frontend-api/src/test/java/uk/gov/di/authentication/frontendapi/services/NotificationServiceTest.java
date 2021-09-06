package uk.gov.di.authentication.frontendapi.services;

import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.services.NotificationService;
import uk.gov.service.notify.NotificationClient;
import uk.gov.service.notify.NotificationClientException;

import java.util.HashMap;
import java.util.Map;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class NotificationServiceTest {

    private static final String TEST_EMAIL = "test@digital.cabinet-office.gov.uk";
    private static final String TEST_PHONE_NUMBER = "01234567890";
    private final NotificationClient notificationClient = mock(NotificationClient.class);
    private final NotificationService notificationService =
            new NotificationService(notificationClient);

    @Test
    public void shouldCallNotifyClientToSendEmail() throws NotificationClientException {
        Map<String, Object> emailPersonalisation = new HashMap<>();
        emailPersonalisation.put("validation-code", "some-code");
        emailPersonalisation.put("email-address", TEST_EMAIL);
        String templateId = "email-template-id";
        notificationService.sendEmail(TEST_EMAIL, emailPersonalisation, templateId);

        verify(notificationClient).sendEmail(templateId, TEST_EMAIL, emailPersonalisation, "");
    }

    @Test
    public void shouldCallNotifyClientToSendText() throws NotificationClientException {
        Map<String, Object> phonePersonalisation = new HashMap<>();
        phonePersonalisation.put("validation-code", "some-code");
        String templateId = "phone-template-id";
        notificationService.sendText(TEST_PHONE_NUMBER, phonePersonalisation, templateId);

        verify(notificationClient).sendSms(templateId, TEST_PHONE_NUMBER, phonePersonalisation, "");
    }
}
