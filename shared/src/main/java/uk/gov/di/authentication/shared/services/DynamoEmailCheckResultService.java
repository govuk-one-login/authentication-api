package uk.gov.di.authentication.shared.services;

import uk.gov.di.authentication.shared.entity.EmailCheckResultStore;

import java.util.Optional;

public class DynamoEmailCheckResultService extends BaseDynamoService<EmailCheckResultStore> {

    public DynamoEmailCheckResultService(ConfigurationService configurationService) {
        super(EmailCheckResultStore.class, "email-check-result", configurationService);
    }

    public Optional<EmailCheckResultStore> getEmailCheckStore(String email) {
        return get(email);
    }

    public void saveEmailCheckResult(String email, String status, Long timeToExist) {
        var emailCheckResult =
                new EmailCheckResultStore()
                        .withEmail(email)
                        .withStatus(status)
                        .withTimeToExist(timeToExist);
        put(emailCheckResult);
    }
}
