package uk.gov.di.authentication.services;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.authentication.shared.entity.EmailCheckResultStatus;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoEmailCheckResultService;
import uk.gov.di.authentication.sharedtest.extensions.EmailCheckResultExtension;

import java.time.temporal.ChronoUnit;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DynamoEmailCheckResultServiceIntegrationTest {

    private static String email = "test.user@example.com";
    private static String referenceNumber = "test-reference";
    private static EmailCheckResultStatus status = EmailCheckResultStatus.PENDING;

    DynamoEmailCheckResultService dynamoEmailCheckResultService =
            new DynamoEmailCheckResultService(ConfigurationService.getInstance());

    @RegisterExtension
    protected static final EmailCheckResultExtension emailCheckResultExtension =
            new EmailCheckResultExtension();

    @Test
    void shouldSaveAndReadAnEmailCheckResult() {
        dynamoEmailCheckResultService.saveEmailCheckResult(
                email, status, unixTimePlusNDays(1), referenceNumber);

        var result = dynamoEmailCheckResultService.getEmailCheckStore(email);

        assertTrue(result.isPresent());
        assertThat(result.get().getEmail(), equalTo(email));
        assertThat(result.get().getStatus(), equalTo(status));
        assertThat(result.get().getReferenceNumber(), equalTo(referenceNumber));
    }

    @Test
    void shouldNotReturnAnEmailCheckResultWhenTimeToLiveHasExpired() {
        long unixTimeInThePast =
                NowHelper.nowPlus(-1, ChronoUnit.DAYS).toInstant().getEpochSecond();
        dynamoEmailCheckResultService.saveEmailCheckResult(
                email, status, unixTimeInThePast, referenceNumber);

        var result = dynamoEmailCheckResultService.getEmailCheckStore(email);

        assertFalse(result.isPresent());
    }

    private long unixTimePlusNDays(Integer numberOfDays) {
        return NowHelper.nowPlus(numberOfDays, ChronoUnit.DAYS).toInstant().getEpochSecond();
    }
}
