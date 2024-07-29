package uk.gov.di.authentication.frontendapi.services;

import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.entity.TemplateAware;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.NotificationService;
import uk.gov.di.authentication.sharedtest.helper.CommonTestVariables;
import uk.gov.service.notify.NotificationClient;
import uk.gov.service.notify.NotificationClientException;

import java.util.HashMap;
import java.util.Map;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static uk.gov.di.authentication.frontendapi.services.NotificationServiceTest.FakeNotificationType.FAKE_EMAIL;
import static uk.gov.di.authentication.frontendapi.services.NotificationServiceTest.FakeNotificationType.FAKE_SMS;

class NotificationServiceTest {

    private static final String TEST_EMAIL = "test@digital.cabinet-office.gov.uk";
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
        Map<String, Object> emailPersonalisation = new HashMap<>();
        emailPersonalisation.put("validation-code", "some-code");
        emailPersonalisation.put("email-address", TEST_EMAIL);

        notificationService.sendEmail(TEST_EMAIL, emailPersonalisation, FAKE_EMAIL);

        verify(notificationClient).sendEmail("FAKE_EMAIL", TEST_EMAIL, emailPersonalisation, "");
    }

    @Test
    public void shouldCallNotifyClientToSendText() throws NotificationClientException {
        Map<String, Object> phonePersonalisation = new HashMap<>();
        phonePersonalisation.put("validation-code", "some-code");
        notificationService.sendText(
                CommonTestVariables.UK_MOBILE_NUMBER, phonePersonalisation, FAKE_SMS);

        verify(notificationClient)
                .sendSms(
                        "FAKE_SMS", CommonTestVariables.UK_MOBILE_NUMBER, phonePersonalisation, "");
    }
}
