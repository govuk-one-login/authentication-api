package uk.gov.di.services;

import uk.gov.di.entity.NotificationCode;
import uk.gov.service.notify.NotificationClient;
import uk.gov.service.notify.NotificationClientException;

import java.util.HashMap;
import java.util.Map;

public class NotificationService {

    private NotificationClient notifyClient;

    private final Map<String, NotificationCode> validationCode = new HashMap<>();

    public NotificationService(NotificationClient notifyClient) {
        this.notifyClient = notifyClient;
    }

    public void sendEmail(String email, Map<String, Object> personalisation, String templateId)
            throws NotificationClientException {
        notifyClient.sendEmail(templateId, email, personalisation, "");
    }

    public boolean validateCode(String email, String code) {
        if (!validationCode.containsKey(email)) {
            return false;
        } else if (!validationCode.get(email).getCode().equals(code)) {
            return false;
        } else if (validationCode
                .get(email)
                .getTimeOfIssue()
                .isAfter(validationCode.get(email).getTimeOfIssue().plusMinutes(15))) {
            validationCode.remove(email);
            return false;
        } else {
            validationCode.remove(email);
            return true;
        }
    }
}
