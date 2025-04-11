package uk.gov.di.authentication.shared.services;

import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.entity.TemplateAware;
import uk.gov.service.notify.NotificationClient;
import uk.gov.service.notify.NotificationClientException;

import java.util.HashMap;
import java.util.Map;

import static java.util.Collections.emptyMap;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static uk.gov.di.authentication.shared.services.NotificationServiceTest.FakeNotificationType.FAKE_EMAIL;
import static uk.gov.di.authentication.shared.services.NotificationServiceTest.FakeNotificationType.FAKE_SMS;

public class NotificationServiceTest {
    private static final String TEST_EMAIL = "test@digital.cabinet-office.gov.uk";
    private static final String TEST_PHONE_NUMBER = "01234567890";
    private final NotificationClient notificationClient = mock(NotificationClient.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final NotificationService notificationService =
            new NotificationService(notificationClient, configurationService);

    enum FakeNotificationType implements TemplateAware {
        FAKE_EMAIL,
        FAKE_SMS;

        public String getTemplateId(ConfigurationService configurationService) {
            return name();
        }
    }

    @Test
    public void shouldCallNotifyClientToSendEmail() throws NotificationClientException {
        // Arrange
        Map<String, Object> emailPersonalisation = new HashMap<>();
        emailPersonalisation.put("validation-code", "some-code");
        emailPersonalisation.put("email-address", TEST_EMAIL);

        // Act
        notificationService.sendEmail(TEST_EMAIL, emailPersonalisation, FAKE_EMAIL);

        // Assert
        verify(notificationClient).sendEmail("FAKE_EMAIL", TEST_EMAIL, emailPersonalisation, "");
    }

    @Test
    void shouldCallNotifyClientToSendEmailWithReference() throws NotificationClientException {
        // Act
        notificationService.sendEmail(TEST_EMAIL, emptyMap(), FAKE_EMAIL, "some-reference-id");

        // Assert
        verify(notificationClient)
                .sendEmail("FAKE_EMAIL", TEST_EMAIL, emptyMap(), "some-reference-id");
    }

    @Test
    public void shouldCallNotifyClientToSendText() throws NotificationClientException {
        // Arrange
        Map<String, Object> phonePersonalisation = new HashMap<>();
        phonePersonalisation.put("validation-code", "some-code");

        // Act
        notificationService.sendText(TEST_PHONE_NUMBER, phonePersonalisation, FAKE_SMS);

        // Assert
        verify(notificationClient).sendSms("FAKE_SMS", TEST_PHONE_NUMBER, phonePersonalisation, "");
    }

    @Test
    void shouldCallNotifyClientToSendTextWithReference() throws NotificationClientException {
        // Act
        notificationService.sendText(TEST_PHONE_NUMBER, emptyMap(), FAKE_SMS, "some-reference-id");

        // Assert
        verify(notificationClient)
                .sendSms("FAKE_SMS", TEST_PHONE_NUMBER, emptyMap(), "some-reference-id");
    }
}
