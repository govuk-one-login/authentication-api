package uk.gov.di.authentication.services;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import uk.gov.di.authentication.shared.entity.EmailCheckResultStatus;
import uk.gov.di.authentication.shared.helpers.CommonTestVariables;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoEmailCheckResultService;
import uk.gov.di.authentication.sharedtest.extensions.EmailCheckResultExtension;

import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.authentication.shared.helpers.NowHelper.unixTimePlusNDays;

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
        var testResponseData = CommonTestVariables.EMAIL_CHECK_RESPONSE_TEST_DATA;

        dynamoEmailCheckResultService.saveEmailCheckResult(
                email,
                status,
                unixTimePlusNDays(1),
                referenceNumber,
                CommonTestVariables.JOURNEY_ID,
                testResponseData);

        var result = dynamoEmailCheckResultService.getEmailCheckStore(email);

        assertTrue(result.isPresent());
        assertThat(result.get().getEmail(), equalTo(email));
        assertThat(result.get().getStatus(), equalTo(status));
        assertThat(result.get().getReferenceNumber(), equalTo(referenceNumber));

        var responseSection = result.get().getEmailCheckResponse();
        assertNotNull(responseSection);

        var responseMap = (Map<?, ?>) responseSection;
        assertThat(responseMap.get("testString"), equalTo("testValue1"));
        assertThat(((Number) responseMap.get("testNumber")).intValue(), equalTo(456));
        assertThat(responseMap.get("testBoolean"), equalTo(true));

        var testArray = (List<?>) responseMap.get("testArray");
        assertThat(testArray.size(), equalTo(2));
        assertThat(testArray.get(0), equalTo("testItem1"));
        assertThat(testArray.get(1), equalTo("testItem2"));

        var testObject = (Map<?, ?>) responseMap.get("testObject");
        assertThat(testObject.get("testNestedString"), equalTo("testNestedValue"));
        assertThat(((Number) testObject.get("testNestedNumber")).intValue(), equalTo(789));
    }

    @Test
    void shouldNotReturnAnEmailCheckResultWhenTimeToLiveHasExpired() {
        long unixTimeInThePast =
                NowHelper.nowPlus(-1, ChronoUnit.DAYS).toInstant().getEpochSecond();
        dynamoEmailCheckResultService.saveEmailCheckResult(
                email,
                status,
                unixTimeInThePast,
                referenceNumber,
                CommonTestVariables.JOURNEY_ID,
                CommonTestVariables.EMAIL_CHECK_RESPONSE_TEST_DATA);

        var result = dynamoEmailCheckResultService.getEmailCheckStore(email);

        assertFalse(result.isPresent());
    }
}
