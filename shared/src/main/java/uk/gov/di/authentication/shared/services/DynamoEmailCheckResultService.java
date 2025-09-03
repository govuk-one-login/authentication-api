package uk.gov.di.authentication.shared.services;

import uk.gov.di.authentication.shared.entity.EmailCheckResultStatus;
import uk.gov.di.authentication.shared.entity.EmailCheckResultStore;
import uk.gov.di.authentication.shared.helpers.NowHelper;

import java.util.Optional;

public class DynamoEmailCheckResultService extends BaseDynamoService<EmailCheckResultStore> {

    public DynamoEmailCheckResultService(ConfigurationService configurationService) {
        super(EmailCheckResultStore.class, "email-check-result", configurationService);
    }

    public Optional<EmailCheckResultStore> getEmailCheckStore(String email) {
        return get(email)
                .filter(t -> t.getTimeToExist() > NowHelper.now().toInstant().getEpochSecond());
    }

    public void saveEmailCheckResult(
            String email,
            EmailCheckResultStatus status,
            Long timeToExist,
            String referenceNumber,
            String govukSigninJourneyId,
            Object emailCheckResponse) {
        var emailCheckResult =
                new EmailCheckResultStore()
                        .withEmail(email)
                        .withStatus(status)
                        .withTimeToExist(timeToExist)
                        .withReferenceNumber(referenceNumber);

        if (govukSigninJourneyId != null) {
            emailCheckResult.withGovukSigninJourneyId(govukSigninJourneyId);
        }

        if (emailCheckResponse != null) {
            emailCheckResult.withEmailCheckResponse(emailCheckResponse);
        }

        put(emailCheckResult);
    }
}
