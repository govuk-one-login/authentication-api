package uk.gov.di.authentication.services;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoEmailCheckResultService;
import uk.gov.di.authentication.sharedtest.extensions.EmailCheckResultExtension;

import java.time.temporal.ChronoUnit;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DynamoEmailCheckResultServiceIntegrationTest {

    private static String email = "test.user@example.com";
    private static String status = "some-status";

    DynamoEmailCheckResultService dynamoEmailCheckResultService =
            new DynamoEmailCheckResultService(ConfigurationService.getInstance());

    @RegisterExtension
    protected static final EmailCheckResultExtension emailCheckResultExtension =
            new EmailCheckResultExtension();

    @Test
    void shouldSaveAndReadAnEmailCheckResult() {
        dynamoEmailCheckResultService.saveEmailCheckResult(email, status, unixTimePlusNDays(1));

        var result = dynamoEmailCheckResultService.getEmailCheckStore(email);

        assertTrue(result.isPresent());
        assertThat(result.get().getEmail(), equalTo(email));
        assertThat(result.get().getStatus(), equalTo(status));
    }

    private long unixTimePlusNDays(Integer numberOfDays) {
        return NowHelper.nowPlus(numberOfDays, ChronoUnit.DAYS).toInstant().getEpochSecond();
    }
}
